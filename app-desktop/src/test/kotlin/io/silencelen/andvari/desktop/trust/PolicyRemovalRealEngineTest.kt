package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.engine.VaultCacheFiles
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A server's policy that forbids a copy of the vault on devices, over the shared code's REAL engine on this computer's
 * stores (as [TrustSeam] builds it) and the shared code's test server, with an item plane in front of it: the shared code
 * tries once to send what waits in the copy, counts, and removes the copy itself; the desktop deletes nothing of it and
 * keeps the sign-in switch as it is until the copy is gone, and only then switches it off. Meanwhile the removal's line
 * stands where "stopped" would, Save stays offered, and an editor keeps what was typed across the new content.
 */
class PolicyRemovalRealEngineTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /**
     * The test server with an honest item plane (the personal vault's row, each change taken once by its id) and a policy
     * that allows the copy until [forbid]. [down]: no answer to a sync or a push; [upAfterPolicy]: the network comes back
     * with the first policy read; [pushGate]: each push waits for it after the server took the change.
     */
    private class ItemServer(private val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var down = false
        var upAfterPolicy = false
        var forbid = false
        var pushGate: CompletableDeferred<Unit>? = null
        var rev = 1L
        val items = ArrayList<SyncItem>()
        val taken = LinkedHashSet<String>()
        val pushed = ArrayList<String>()

        private fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            when (route) {
                WireRoute.CLIENT_POLICY -> {
                    if (upAfterPolicy) down = false
                    WireResult.Ok(decode(policy(forbid)), 200)
                }
                WireRoute.SYNC -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    pushed += b.mutations.map { it.mutationId }
                    val results = b.mutations.map { m ->
                        if (taken.add(m.mutationId)) {
                            rev++
                            items.removeAll { it.itemId == m.itemId }
                            val up = m.item
                            items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                                up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                        }
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    pushGate?.await()
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
    }

    private inline fun <reified T : EntryScreen> DesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun signUp(a: DesktopAppApi) {
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

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    /** The vault's items section, as the window draws it, with the focus walk and the editor's draft recorded. */
    @OptIn(androidx.compose.ui.InternalComposeUiApi::class)
    private class Items(m: TrustModel) {
        val focus = ArrayList<String>()
        val drafts = ArrayList<EditorDraft>()
        private var t = 0L
        private val scene = ImageComposeScene(900, 2400, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides focus, LocalEditorShown provides { drafts += it }, LocalFault provides m.fault) {
                MaterialTheme { VaultItemsSection(m) }
            }
        }

        fun render() = repeat(2) {
            t += 50_000_000L
            scene.render(t)
        }

        init {
            render()
        }

        private fun press(key: Key) {
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyDown))
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyUp))
            render()
        }

        fun tabUntil(words: String, most: Int = 80) {
            repeat(most) {
                if (focus.lastOrNull() == words) return
                press(Key.Tab)
            }
            assertEquals(words, focus.lastOrNull(), focus.toString())
        }

        /** Backwards: the editor's notes take a Tab as a character, so its Save, the last control, is reached from the end. */
        fun backUntil(words: String, most: Int = 20) {
            repeat(most) {
                if (focus.lastOrNull() == words) return
                scene.sendKeyEvent(KeyEvent(Key.Tab, KeyEventType.KeyDown, isShiftPressed = true))
                scene.sendKeyEvent(KeyEvent(Key.Tab, KeyEventType.KeyUp, isShiftPressed = true))
                render()
            }
            assertEquals(words, focus.lastOrNull(), focus.toString())
        }

        fun enter() = press(Key.Enter)

        fun close() = scene.close()
    }

    @Test
    fun theDesktopDeletesNothingAheadOfTheSharedCodeWhichSendsWhatWaitsOnceCountsAndRemovesTheCopy() = runBlocking<Unit> {
        val instance = FakeInstance(crypto)
        val server = ItemServer(instance)
        val dir = java.nio.file.Files.createTempDirectory("andvari-policywipe").toFile()
        val home = DesktopHome(dir, NoKeyStore, log = {}, keyStorePause = {})
        // Every removal of a cache file, by whichever road: the shared code's goes through the files it was handed.
        val deleted = ArrayList<String>()
        val files = object : VaultCacheFiles by home.cacheFiles {
            override fun delete(fileName: String): Boolean {
                deleted += fileName
                return home.cacheFiles.delete(fileName)
            }
        }
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(), deviceName = "test", transport = BearerTransport(mapOf(instance.origin to server)),
                state = JsonDeviceState(home.stateFile()), secure = JsonDeviceState(home.secureFile), requestStore = JsonDeviceState(home.requestFile),
                crypto = crypto, clock = { instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, contentStores = home.content.stores, keepsAtRest = home::keepsAtRest,
            ),
        )
        home.consentWithdrawn = api::atRestConsentChanged
        val faults = ArrayList<String>()
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, HomeSignInKeeping(home), faultLog = { faults += it })
        var items: Items? = null
        try {
            m.start()
            m.onSnapshot(api.snapshot)
            signUp(api)
            m.onSnapshot(api.snapshot)
            // "Keep me signed in": this computer has no key store, so in a file only this account can read.
            m.setKeepSignIn(true)
            m.answerNoKeyStore(true)
            assertTrue(m.keepSignIn.value)
            // Opened again under the allowing policy: the copy is a file on this computer.
            api.lock()
            m.onSnapshot(api.snapshot)
            assertEquals(VaultUnlockResult.DONE, api.unlock(assertNotNull(api.snapshot.locked), strong))
            m.onSnapshot(api.snapshot)
            assertTrue(home.vaultFileOnDisk(), "the copy is at rest")
            val first = assertNotNull(api.content)
            assertEquals(ActionResult.Ok, first.syncQuietly())
            // Two changes made offline wait in the copy.
            server.down = true
            for (i in 1..2) assertEquals(ActionResult.Ok, first.saveLogin(null, login("Site$i"), null))
            api.lock()
            m.onSnapshot(api.snapshot)

            // The server forbids the copy from its next policy read; the network is back then; the answer to the one
            // try waits until released.
            server.forbid = true
            server.upAfterPolicy = true
            val gate = CompletableDeferred<Unit>()
            server.pushGate = gate
            assertEquals(VaultUnlockResult.DONE, api.unlock(assertNotNull(api.snapshot.locked), strong))
            m.onSnapshot(api.snapshot)
            assertEquals(2, server.pushed.size, "the one try is under way")
            assertTrue(m.keepForbidden())
            // Owed, as the snapshot says for the session's own account (the desktop no longer looks at the disk).
            assertTrue(api.snapshot.policyWipeOwed)
            assertTrue(m.policyRemovalOwed())

            // The shared code owes the removal: the desktop deletes nothing and switches nothing off.
            assertTrue(m.keepSignIn.value, "the switch stays as it is while the copy is owed")
            assertTrue(home.vaultFileOnDisk(), "the copy is still on disk")
            assertEquals(emptyList(), deleted)
            // Unticking deletes nothing ahead of it either: the removal's own line is said.
            val during = assertNotNull(m.content.value)
            val line = assertNotNull(during.state.removingLine)
            m.setKeepSignIn(false)
            assertTrue(m.keepSignIn.value)
            assertTrue(home.vaultFileOnDisk())
            assertEquals(line, assertIs<UiText.Plain>(assertNotNull(m.said.value).text).text)
            // The line stands where "stopped" would; Save stays offered.
            assertEquals(line, assertIs<UiText.Plain>(syncLine(during.state)).text)
            assertTrue(canSaveState(during.state))

            // A new item's editor, opened from the list: what is typed there; its save meanwhile is refused with the line.
            val w = Items(m).also { items = it }
            w.tabUntil(UiText.ph(Placeholder.ITEM_ADD).shown())
            w.enter()
            val draft = w.drafts.last()
            draft.name = "Typed during the removal"
            draft.username = "me"
            w.render()
            w.backUntil(UiText.ph(Placeholder.ITEM_SAVE).shown())
            w.enter()
            assertTrue(during.state.items.none { it.name == "Typed during the removal" }, "not made")

            // The answer comes: the shared code counts and removes the copy itself, once.
            gate.complete(Unit)
            m.onSnapshot(api.snapshot)
            assertEquals(2, server.taken.size, "both waiting changes reached the server")
            assertEquals(server.pushed.toSet().size, server.pushed.size, "each sent once")
            val notice = assertNotNull(api.snapshot.policyWipe)
            assertEquals(0, notice.notSent)
            assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_NOTHING_LOST), notice.lines.map { it.key })
            assertEquals(1, deleted.size, "removed once, by the shared code's road")
            assertFalse(home.vaultFileOnDisk())
            assertFalse(api.snapshot.policyWipeOwed)
            assertFalse(m.policyRemovalOwed())
            // Only now does the switch go off, with its line.
            assertFalse(m.keepSignIn.value, "off once the copy is gone")
            assertEquals(Placeholder.KEEP_FORBIDDEN, assertIs<UiText.Ph>(assertNotNull(m.said.value).text).placeholder)
            assertEquals(1, deleted.size, "the desktop's own switch deleted no copy")

            // The vault goes on from the server, in memory: a new content, and the editor is still on show with what was
            // typed; its Save now goes through.
            val after = assertNotNull(m.content.value)
            assertNotSame(during, after)
            w.render()
            assertSame(draft, w.drafts.last(), "the same editor, the same draft")
            assertEquals("Typed during the removal", draft.name)
            // The focus is still on its Save (a new editor would have lost it, and the Enter below would save nothing).
            assertEquals(UiText.ph(Placeholder.ITEM_SAVE).shown(), w.focus.last())
            w.enter()
            assertEquals(ActionResult.Ok, after.syncQuietly())
            assertTrue(after.state.items.any { it.name == "Typed during the removal" }, "saved over the new content")
            assertEquals(3, server.taken.size)
            assertEquals(emptyList(), faults)
        } finally {
            items?.close()
            api.close()
            dir.deleteRecursively()
        }
    }
}

/** A vault's cache database (of any account) is on this computer's disk: what the tests look at; the desktop reads the snapshot. */
internal fun DesktopHome.vaultFileOnDisk(): Boolean =
    cacheDir.listFiles()?.any { it.isFile && it.name.startsWith("vault-") && it.name.contains(".db") } == true
