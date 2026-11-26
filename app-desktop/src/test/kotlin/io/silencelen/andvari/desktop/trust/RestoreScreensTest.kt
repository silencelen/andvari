package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.InternalComposeUiApi
import androidx.compose.ui.graphics.asComposeCanvas
import androidx.compose.ui.platform.PlatformContext
import androidx.compose.ui.scene.CanvasLayersComposeScene
import androidx.compose.ui.scene.ComposeSceneContext
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsOwner
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.BackupRestoreApi
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
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupSkippedItem
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.content.ContentStores
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.jetbrains.skia.Surface as SkiaSurface
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.ZoneId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Restore a backup", drawn in each of its states over the shared code's REAL engine and restore on this computer's
 * stores, against the shared code's test server with an item plane in front of it (as the other real-engine walks of
 * the desktop are built), with real backup files made by the shared code's own `Backup.build`. Every line is named by
 * its key ([Placeholder]); the design's approved sentences are compared as the screen draws them.
 */
class RestoreScreensTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val pass = "a backup passphrase for the test"
    private val zone = ZoneId.systemDefault()

    /**
     * The test server with an item plane: the personal vault's row, each change taken once by its id, attached files
     * taken. [quota] is served on every sync; while [rejectFirst], the first change of the next push is refused for good
     * (`item_too_large`), and again each time it comes back; [failNext] answers the next push with a refusal of the whole push (that status); [slowSingle]
     * asks for a wait of one second (`rate_limited`); [pushes] counts the pushes answered.
     */
    private class ItemServer(private val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var quota: QuotaUse? = null

        /** What the server's policy says of an offline copy. */
        var offlineCacheAllowed = true
        var rejectFirst = false
        private var rejected: String? = null
        var failNext: Int? = null
        var pushes = 0
        var rev = 1L

        /** The next push of one new change (the last batch of a restore of 201 items) is asked to wait a second, once. */
        var slowSingle = false
        val items = ArrayList<SyncItem>()
        val taken = LinkedHashSet<String>()
        val uploads = ArrayList<String>()

        private var pushCalls = 0

        /** Shown every push before it is answered, with its number counted from when this was set (1, 2, …). */
        var beforePush: ((Int) -> Unit)? = null
            set(value) {
                pushCalls = 0
                field = value
            }

        /** The next read of the policy waits until this completes, then answers with [offlineCacheAllowed] as it is then. */
        var holdPolicy: CompletableDeferred<Unit>? = null

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            when (route) {
                WireRoute.CLIENT_POLICY -> {
                    holdPolicy?.let { held ->
                        holdPolicy = null
                        held.await()
                    }
                    WireResult.Ok(
                        decode(WireJson.json.encodeToString(ClientPolicy.serializer(), ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, offlineCacheAllowed, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false))),
                        200,
                    )
                }
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0, quota = quota)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    beforePush?.invoke(++pushCalls)
                    val fail = failNext
                    when {
                        fail != null -> {
                            failNext = null
                            WireResult.Refused(fail, WireError("server_error", "test"))
                        }
                        slowSingle && WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!).mutations.let { it.size == 1 && it[0].mutationId !in taken } -> {
                            slowSingle = false
                            WireResult.Refused(429, WireError("rate_limited", "test"), 1)
                        }
                        else -> {
                            pushes++
                            val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                            // As a real server: the change it refused for good is refused again whenever it comes back.
                            if (rejectFirst && rejected == null) rejected = b.mutations.first().mutationId
                            val reject = if (rejectFirst) rejected else null
                            val results = b.mutations.map { m ->
                                if (m.mutationId == reject) {
                                    MutationResult(m.mutationId, MutationStatus.REJECTED, reason = "item_too_large")
                                } else {
                                    if (taken.add(m.mutationId)) {
                                        rev++
                                        items.removeAll { it.itemId == m.itemId }
                                        val up = m.item
                                        items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, false, false, up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                                    }
                                    MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                                }
                            }
                            WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                        }
                    }
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }

        override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route != WireRoute.ATTACHMENT_UPLOAD) return instance.callBytes(route, pathParams, query, body, authenticated, decode)
            val id = pathParams.getValue("attachmentId")
            uploads += id
            val q = query.orEmpty().split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
            val meta = AttachmentMeta(id, q["itemId"].orEmpty(), q["vaultId"].orEmpty(), body.size.toLong(), Bytes.toHexLower(createCryptoProvider().sha256(body)), instance.now)
            return WireResult.Ok(decode(WireJson.json.encodeToString(AttachmentMeta.serializer(), meta)), 200)
        }
    }

    private class World(val server: ItemServer, val api: EngineDesktopAppApi, val m: TrustModel, val home: DesktopHome, val dir: File, val instance: FakeInstance)

    /** [offlineCacheAllowed]: what the server's policy says of an offline copy. */
    private fun world(name: String, offlineCacheAllowed: Boolean = true): World {
        val instance = FakeInstance(crypto)
        val server = ItemServer(instance)
        server.offlineCacheAllowed = offlineCacheAllowed
        val dir = java.nio.file.Files.createTempDirectory("andvari-restore-$name").toFile()
        val w = started(server, instance, dir)
        runBlocking { signUp(w.api, instance) }
        w.m.onSnapshot(w.api.snapshot)
        return w
    }

    /** The app started over [dir], as at a start of the app: a new home, engine and model, nothing of an earlier run in memory. */
    private fun started(server: ItemServer, instance: FakeInstance, dir: File): World {
        val home = DesktopHome(dir, NoKeyStore, log = {}, keyStorePause = {})
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(), deviceName = "test", transport = BearerTransport(mapOf(instance.origin to server)),
                state = JsonDeviceState(home.stateFile()), secure = JsonDeviceState(home.secureFile), requestStore = JsonDeviceState(home.requestFile),
                crypto = crypto, clock = { instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = home.cacheFiles, contentStores = home.content.stores, keepsAtRest = home::keepsAtRest,
            ),
        )
        home.consentWithdrawn = api::atRestConsentChanged
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, HomeSignInKeeping(home), faultLog = {})
        m.start()
        m.onSnapshot(api.snapshot)
        return World(server, api, m, home, dir, instance)
    }

    private inline fun <reified T : EntryScreen> DesktopAppApi.at(): T = snapshot.entry as T

    private suspend fun signUp(a: DesktopAppApi, instance: FakeInstance) {
        val email = "alice@example.com"
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), instance.codes.getValue(email)))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    // ---- the backup files, made by the shared code's own writer ----

    private fun id() = Bytes.uuidV4FromBytes(crypto.randomBytes(16))

    private fun doc(name: String, attachments: List<AttachmentRef> = emptyList()) =
        ItemDoc(type = "login", name = name, login = LoginData(username = "me", password = "pw-$name", uris = listOf("https://$name.test")), attachments = attachments)

    private val personal = BackupVault("11111111-1111-4111-8111-111111111111", "personal", "Personal", "owner")
    private val family = BackupVault("22222222-2222-4222-8222-222222222222", "shared", "Family", "owner")
    private val work = BackupVault("33333333-3333-4333-8333-333333333333", "shared", "Work", "writer")

    /**
     * A backup of [items] in the personal vault ("A" first), two shared vaults of two items each (one owned, one a
     * member's), one attached file on "A" (70 000 bytes), one name in each list of what the file could not hold, and
     * the first item's id written a second time (left out).
     */
    private fun backup(items: Int, fileId: String = id(), origin: String = "https://vault.example.org", kdf: KdfParams = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), passphrase: String = pass): ByteArray {
        val fileKey = crypto.randomBytes(32)
        val attachmentId = id()
        val plain = ByteArray(70_000) { (it % 251).toByte() }
        val first = BackupItem(id(), personal.vaultId, 1, 0, doc("A", listOf(AttachmentRef(attachmentId, "scan.pdf", plain.size.toLong(), Bytes.toB64(fileKey)))))
        val rest = (2..items).map { BackupItem(id(), personal.vaultId, 1, 0, doc("Item $it")) }
        val shared = listOf(family, family, work, work).mapIndexed { i, v -> BackupItem(id(), v.vaultId, 1, 0, doc("${v.name} $i")) }
        val payload = BackupPayload(
            exportedAt = 1_794_484_800_000L, origin = origin, vaults = listOf(personal, family, work),
            items = listOf(first) + rest + shared + first.copy(doc = doc("A again")),
            attachments = listOf(BackupAttachmentEntry(1, attachmentId, first.itemId, "scan.pdf", plain.size.toLong(), Bytes.toB64(fileKey))),
            skipped = BackupSkipped(listOf(BackupSkippedItem(id(), personal.vaultId, 1)), listOf("big.mov"), listOf("lost.png")),
        )
        val out = ByteArrayOutputStream()
        Backup.build(crypto, passphrase, fileId, crypto.randomBytes(16), kdf, payload, listOf(Backup.AttachmentSection(fileKey) { plain.copyOf() })) { out.write(it) }
        return out.toByteArray()
    }

    /** A backup of one personal item and nothing else. */
    private fun small(): ByteArray {
        val payload = BackupPayload(exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal), items = listOf(BackupItem(id(), personal.vaultId, 1, 0, doc("Only"))))
        val out = ByteArrayOutputStream()
        Backup.build(crypto, pass, id(), crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload) { out.write(it) }
        return out.toByteArray()
    }

    // ---- drawing ----

    /** [content] drawn in a window of the desktop's width; [lines] are the texts on it, top to bottom. */
    @OptIn(InternalComposeUiApi::class)
    private class Drawn(content: @Composable () -> Unit) {
        private val owners = LinkedHashSet<SemanticsOwner>()
        private val surface = SkiaSurface.makeRasterN32Premul(WIDTH, HEIGHT)
        private var t = 0L
        private val scene = CanvasLayersComposeScene(
            Density(1f), LayoutDirection.Ltr, IntSize(WIDTH, HEIGHT), Dispatchers.Unconfined,
            object : ComposeSceneContext {
                override val platformContext: PlatformContext = object : PlatformContext by PlatformContext.Empty {
                    override val semanticsOwnerListener: PlatformContext.SemanticsOwnerListener = object : PlatformContext.SemanticsOwnerListener {
                        override fun onSemanticsOwnerAppended(semanticsOwner: SemanticsOwner) {
                            owners += semanticsOwner
                        }

                        override fun onSemanticsOwnerRemoved(semanticsOwner: SemanticsOwner) {
                            owners -= semanticsOwner
                        }

                        override fun onSemanticsChange(semanticsOwner: SemanticsOwner) {}

                        override fun onLayoutChange(semanticsOwner: SemanticsOwner, semanticsNodeId: Int) {}
                    }
                }
            },
            {},
        )

        init {
            scene.setContent { MaterialTheme { Surface { Column { content() } } } }
        }

        fun lines(): List<String> {
            repeat(3) {
                t += 50_000_000L
                surface.canvas.clear(0)
                scene.render(surface.canvas.asComposeCanvas(), t)
            }
            return owners.toList().flatMap { it.getAllSemanticsNodes(mergingEnabled = false) }
                .filter { it.boundsInRoot.let { b -> b.width > 0f && b.height > 0f } }
                .sortedBy { it.boundsInRoot.top }
                .mapNotNull(::textOf)
        }

        fun close() = scene.close()

        private fun textOf(n: SemanticsNode): String? =
            (n.config.getOrNull(SemanticsProperties.Text).orEmpty() + listOfNotNull(n.config.getOrNull(SemanticsProperties.EditableText)))
                .joinToString(" ") { it.text }.takeIf { it.isNotBlank() }

        companion object {
            const val WIDTH = 900
            const val HEIGHT = 4000
        }
    }

    private fun page(w: World, flow: RestoreFlow): List<String> {
        val d = Drawn { RestorePage(w.m, flow) }
        try {
            return d.lines()
        } finally {
            d.close()
        }
    }

    private fun ph(p: Placeholder, vararg args: String) = UiText.ph(p, *args).shown()

    private fun has(lines: List<String>, vararg expected: String) {
        for (e in expected) assertTrue(e in lines, "drawn: \"$e\" in $lines")
    }

    private fun flow(w: World, bytes: ByteArray, name: String = "family.andvari"): RestoreFlow {
        val c = assertNotNull(w.m.content.value, "the vault is open")
        w.m.openRestore(c, name, bytes)
        return assertNotNull(w.m.restoring.value)
    }

    private fun open(f: RestoreFlow, passphrase: String = pass) = runBlocking { f.open(passphrase.toCharArray()) }

    // ---- the entry and the passphrase ----

    @Test
    fun theThirdEntryOfTheBackupCardOpensThePassphraseStepWhichSaysWhoseItIsAndWhatAFileThatDoesNotOpenIs() {
        val w = world("entry")
        // The card holds the third entry under the two exports.
        val card = Drawn { BackupSection(w.m) }
        try {
            val lines = card.lines()
            has(lines, "Export an encrypted backup", "Export a CSV file", "Restore a backup")
            assertTrue(lines.indexOf("Restore a backup") > lines.indexOf("Export a CSV file"))
            // A picked file opens the restore in the card's place.
            val f = flow(w, backup(3), "family.andvari")
            val step = card.lines()
            has(step, "Restore a backup", "family.andvari", "This is the passphrase of the backup, not your master password.", ph(Placeholder.EXPORT_PASSPHRASE), ph(Placeholder.RESTORE_OPEN))
            assertFalse("Export an encrypted backup" in step, "the restore stands in the card's place")
            // A wrong passphrase.
            open(f, "not the passphrase")
            has(card.lines(), "The backup does not open with this passphrase, or the file is damaged.")
            assertEquals(RestoreFlow.Stage.PASSPHRASE, f.views.value.stage)
        } finally {
            card.close()
        }
        // A file that is no backup; one too large for any backup has a line of its own.
        val junk = flow(w, ByteArray(4000) { 7 }, "notes.txt")
        open(junk)
        has(page(w, junk), "This is not an andvari backup file, or it is damaged.")
        assertEquals(UiText.ph(Placeholder.RESTORE_TOO_LARGE).shown(), RestoreFlow.notOpenedLine(Backup.ERR_TOO_LARGE).shown())
        // A file whose id is not the form every app writes, and one whose key derivation asks more than a backup may.
        val upper = flow(w, backup(1, fileId = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"))
        open(upper)
        has(page(w, upper), ph(Placeholder.RESTORE_ID_REFUSED))
        val costly = flow(w, backup(1, kdf = KdfParams(ops = 17, memBytes = 8 * 1024 * 1024)))
        open(costly)
        has(page(w, costly), ph(Placeholder.RESTORE_NOT_OPENED, Backup.ERR_UNSUPPORTED_KDF))
        // A lock ends the restore on screen.
        runBlocking { w.api.lock() }
        w.m.onSnapshot(w.api.snapshot)
        assertNull(w.m.restoring.value)
    }

    // ---- the preview, the run, its stop, its end, and the same file again ----

    @Test
    fun aRestoreFromThePreviewThroughNoRoomAStopAWaitAndARefusedItemToTheSameFileAgain() {
        val w = world("walk")
        val c = assertNotNull(w.m.content.value)
        // The account already holds two items.
        runBlocking {
            assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Mine 1", "me", "pw-1", listOf("https://one.test"), "", "", false), null))
            assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Mine 2", "me", "pw-2", listOf("https://two.test"), "", "", false), null))
        }
        val bytes = backup(201)
        val f = flow(w, bytes)
        val sent = w.server.pushes
        open(f)

        // The preview: nothing written yet; the personal vault ticked, each shared vault on its own line and not ticked.
        val seen = page(w, f)
        val v = f.views.value
        assertEquals(RestoreFlow.Stage.PREVIEW, v.stage)
        assertEquals(setOf(personal.vaultId), v.chosen, "only the personal vault is ticked")
        assertEquals(sent, w.server.pushes, "nothing is sent before the confirm")
        has(
            seen,
            "Made on ${RestoreFlow.dayText(1_794_484_800_000L, zone)} from vault.example.org.",
            "Personal vault: 201 items",
            "Family: 2 items. You owned it.",
            "Work: 2 items. You were a member.",
            "Attached files: 1 (${sizeText(70_000)}).",
            "1 attached file was too large for the backup. Attach it again by hand.",
            ph(Placeholder.RESTORE_FETCH_FAILED, "1"),
            "1 item could not be read by the device that made the backup.",
            "Not in any backup: two-step sign-in, earlier versions of items, the trash.",
            "This account already holds 2 items. Restoring adds the backup's items beside them. Nothing is replaced, and an item you have in both will be there twice.",
            ph(Placeholder.RESTORE_LEFT_OUT_ITEMS_TWICE, "1"),
            "Run a restore from one computer.",
            "Restore 201 items",
        )
        // A shared vault ticked adds its items to the button; unticked again, it goes.
        f.choose(work.vaultId, true)
        has(page(w, f), "Restore 203 items")
        f.choose(work.vaultId, false)

        // No room: the design's line, then the limit and by how much in core's words; nothing written.
        w.server.quota = QuotaUse(QuotaMeter(0, 100L * 1024 * 1024), QuotaMeter(2, 100), QuotaMeter(0, 50), QuotaMeter(0, 10))
        runBlocking { f.confirm() }
        val short = page(w, f)
        has(short, "There is not enough room in this account", UiText.filled(CopyKey.SPACE_SHORT_ITEMS, "100", "103").shown(), "Restore 201 items")
        assertEquals(sent, w.server.pushes, "nothing written")
        assertEquals(2, w.server.items.size)
        w.server.quota = null

        // A stop: the server refuses the whole first push; Try again is offered.
        w.server.failNext = 503
        runBlocking { f.confirm() }
        val stop = assertNotNull(f.views.value.stop)
        has(page(w, f), ph(Placeholder.RESTORE_STOPPED, RestoreFlow.stopReason(stop)), "Try again")
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)

        // Try again: the first item is refused for good, and the second push is asked to wait one second.
        w.server.rejectFirst = true
        // The wait comes at the second batch (one item), so the run has said how far it is.
        w.server.slowSingle = true
        runBlocking {
            val run = launch(Dispatchers.Unconfined) { f.tryAgain() }
            val running = page(w, f)
            assertEquals(RestoreFlow.Stage.RUNNING, f.views.value.stage)
            has(running, "Restoring: 200 of 201 items.", ph(Placeholder.RESTORE_WAITING, waitText(1).shown()))
            run.join()
        }
        // The end: what was stored, the refused item by its name with Try again, and what was left out.
        val end = page(w, f)
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        has(end, "200 items restored into 1 vault.", ph(Placeholder.RESTORE_REFUSED, "“A”"), ph(Placeholder.RESTORE_LEFT_OUT_ITEMS_TWICE, "1"), "Try again")
        assertEquals(202, w.server.items.size, "two of the account's own and 200 of the file's")

        // Try again, the server taking it now: the refused item goes, with its attached file, and nothing is stored twice.
        w.server.rejectFirst = false
        runBlocking { f.tryAgain() }
        val again = page(w, f)
        has(again, ph(Placeholder.RESTORE_DONE_ONE, "1", "1"), "1 attached file restored.")
        assertFalse(again.any { it == "Try again" }, "nothing left to try again")
        assertEquals(203, w.server.items.size, "every item once")
        assertEquals(1, w.server.uploads.toSet().size)

        // The same file again: the personal vault is said as restored, with its day, and only the shared vaults are offered.
        val second = flow(w, bytes)
        open(second)
        val offered = page(w, second)
        val p = assertNotNull(second.views.value.preview)
        val at = assertNotNull(p.vaults.first { it.personal }.restoredAt)
        has(
            offered,
            ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 201 items.",RestoreFlow.dayText(at, zone)),
            "Family: 2 items. You owned it.",
            // Only the account's own two: the 201 came from this file's restore on this computer.
            "This account already holds 2 items. Restoring adds the backup's items beside them. Nothing is replaced, and an item you have in both will be there twice.",
            "Restore 0 items",
        )
        assertEquals(emptySet(), second.views.value.chosen)
        runBlocking { second.confirm() }
        assertEquals(203, w.server.items.size, "nothing ticked: nothing sent")
    }

    @Test
    fun aFileWhoseEveryVaultIsRestoredSaysSoAndOffersNoRestore() {
        val w = world("nothing-left")
        val bytes = small()
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        has(page(w, f), ph(Placeholder.RESTORE_DONE_ONE, "1", "1"))
        val again = flow(w, bytes)
        open(again)
        val lines = page(w, again)
        has(lines, ph(Placeholder.RESTORE_NOTHING_LEFT))
        assertFalse(lines.any { it.startsWith("Restore ") && it != "Restore a backup" }, "no restore button: $lines")
        assertEquals(1, w.server.items.size)
    }

    @Test
    fun aFileThatNamesNoServerSaysOnlyItsDay() {
        val w = world("unnamed")
        val f = flow(w, backup(1, origin = ""))
        open(f)
        has(page(w, f), ph(Placeholder.RESTORE_MADE_UNNAMED, RestoreFlow.dayText(1_794_484_800_000L, zone)))
    }

    // ---- a record this computer keeps in memory only ----

    /** The preview and then a stop of [w]'s restore of a small file: the lines drawn at each. */
    private fun previewAndStop(w: World): Pair<List<String>, List<String>> {
        val f = flow(w, small())
        open(f)
        val preview = page(w, f)
        w.server.failNext = 503
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        return preview to page(w, f)
    }

    /** "Keep me signed in" ticked as the person ticks it (a file only this account can read), then locked and unlocked. */
    private fun keepAndOpenAgain(w: World) {
        w.m.setKeepSignIn(true)
        w.m.answerNoKeyStore(true)
        assertTrue(w.m.keepSignIn.value)
        w.api.lock()
        w.m.onSnapshot(w.api.snapshot)
        runBlocking { assertEquals(VaultUnlockResult.DONE, w.api.unlock(assertNotNull(w.api.snapshot.locked), strong)) }
        w.m.onSnapshot(w.api.snapshot)
        assertTrue(w.home.keepsAtRest())
    }

    @Test
    fun aRecordKeptInMemoryOnlyIsSaidAboveTheButtonAndAgainAtTheStop() {
        val line = ph(Placeholder.RESTORE_MEMORY_ONLY)
        // The policy allows a copy, and "Keep me signed in on this computer" is off: memory only.
        val switchOff = previewAndStop(world("memory-switch-off"))
        val one = RestoreFlow.confirmLine(1).shown()
        has(switchOff.first, line, one)
        assertTrue(switchOff.first.indexOf(line) < switchOff.first.indexOf(one), "above the button: ${switchOff.first}")
        has(switchOff.second, line, "Try again")

        // The policy forbids a copy, and the switch is on: memory only.
        val forbidding = world("memory-policy-forbids", offlineCacheAllowed = false)
        forbidding.home.setKeepSignIn(true, null, plainFile = true)
        assertTrue(forbidding.home.keepsAtRest())
        val policyForbids = previewAndStop(forbidding)
        has(policyForbids.first, line)
        has(policyForbids.second, line)

        // Both allow (the switch on before the vault first opened): the record is a file of this computer, and the line
        // is not drawn.
        val first = world("memory-both-allow")
        keepAndOpenAgain(first)
        // The run that signed the account up holds the content's kept records in this process's memory until it ends; the
        // restore's record is a file all the same, and no line is owed in that run either.
        assertEquals(false, first.api.restores.recordInMemoryOnly())
        first.api.lock()
        first.m.onSnapshot(first.api.snapshot)
        // The app closed and started again over the same folder, then unlocked.
        val allowing = started(first.server, first.instance, first.dir)
        runBlocking { assertEquals(VaultUnlockResult.DONE, allowing.api.unlock(assertNotNull(allowing.api.snapshot.locked), strong)) }
        allowing.m.onSnapshot(allowing.api.snapshot)
        assertEquals(false, allowing.api.restores.recordInMemoryOnly())
        val both = previewAndStop(allowing)
        assertFalse(line in both.first, "${both.first}")
        assertFalse(line in both.second, "${both.second}")
        has(both.first, RestoreFlow.confirmLine(1).shown())
    }

    // ---- a run without the server's figures, and an end that took files off ----

    @Test
    fun aRunWithoutTheServersFiguresSaysTheRoomWasNotCheckedAndTheEndSaysTheFilesTakenOff() {
        val w = world("room-unknown")
        val unknown = ph(Placeholder.RESTORE_ROOM_UNKNOWN)
        // "B" names an attached file the backup does not hold, as a backup made without its attached files writes it.
        val payload = BackupPayload(
            exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal),
            items = listOf(BackupItem(id(), personal.vaultId, 1, 0, doc("B", listOf(AttachmentRef(id(), "left.pdf", 10, Bytes.toB64(crypto.randomBytes(32))))))),
        )
        val out = ByteArrayOutputStream()
        Backup.build(crypto, pass, id(), crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload) { out.write(it) }
        val f = flow(w, out.toByteArray())
        open(f)
        // Without the server's figures: the run, here stopped, says the room was not checked.
        w.server.quota = null
        w.server.failNext = 503
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        has(page(w, f), unknown)
        // With them: checked, and the run says nothing of it. The end: the file "B" names is not in the backup, and the
        // end says one file was taken off.
        w.server.quota = QuotaUse(QuotaMeter(0, 100L * 1024 * 1024), QuotaMeter(0, 100), QuotaMeter(0, 50), QuotaMeter(0, 10))
        runBlocking { f.tryAgain() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        assertFalse(f.views.value.roomUnknown)
        assertFalse(RestoreFlow.runLines(f.views.value).any { it.shown() == unknown })
        val end = page(w, f)
        has(end, ph(Placeholder.RESTORE_DONE_ONE, "1", "1"), ph(Placeholder.RESTORE_DONE_STRIPPED, "1"))
        assertFalse(unknown in end)
    }

    // ---- a restore stopped half-way goes on after the app was closed (the approved sentence, decided on 22 November 2026) ----

    /** "Keep me signed in" ticked as the person ticks it (a file only this account can read), in this run. */
    private fun keepOn(w: World) {
        w.m.setKeepSignIn(true)
        w.m.answerNoKeyStore(true)
        assertTrue(w.home.keepsAtRest())
    }

    /** [w] locked and unlocked again in the same run. */
    private fun lockAndUnlock(w: World) {
        w.api.lock()
        w.m.onSnapshot(w.api.snapshot)
        runBlocking { assertEquals(VaultUnlockResult.DONE, w.api.unlock(assertNotNull(w.api.snapshot.locked), strong)) }
        w.m.onSnapshot(w.api.snapshot)
    }

    /** [w] locked, then the app started again over its folder and unlocked: nothing of the earlier run in memory. */
    private fun restart(w: World): World {
        w.api.lock()
        w.m.onSnapshot(w.api.snapshot)
        val again = started(w.server, w.instance, w.dir)
        runBlocking { assertEquals(VaultUnlockResult.DONE, again.api.unlock(assertNotNull(again.api.snapshot.locked), strong)) }
        again.m.onSnapshot(again.api.snapshot)
        return again
    }

    /** [w]'s restore of [bytes] (its personal vault), stopped by a refused push once [taken] pushes were taken. */
    private fun stopAfter(w: World, bytes: ByteArray, taken: Int) {
        val f = flow(w, bytes)
        open(f)
        w.server.beforePush = { n -> if (n == taken + 1) w.server.failNext = 503 }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
    }

    /** The same file chosen again in [w], its personal vault confirmed: it runs to its end. */
    private fun goOn(w: World, bytes: ByteArray) {
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage, "${f.views.value.stop}")
    }

    /** The files of restore records in [w]'s folder (a record's file, and any copy of it being replaced). */
    private fun restoreFiles(w: World): List<File> = w.dir.walkTopDown().filter { it.isFile && ContentStores.RESTORES in it.name }.toList()

    private suspend fun signIn(a: DesktopAppApi, instance: FakeInstance) {
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), instance.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, a.entry.submitSignIn(a.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    @Test
    fun aRestoreStoppedHalfWayInTheRunThatSignedUpGoesOnAfterANewStartAndStoresNothingTwice() {
        val w = world("first-run")
        keepOn(w)
        val bytes = backup(401)
        stopAfter(w, bytes, taken = 1)
        assertEquals(200, w.server.items.size, "the first batch stored")
        val inMemory = w.api.restores.recordInMemoryOnly()
        val files = restoreFiles(w)
        val again = restart(w)
        goOn(again, bytes)
        assertEquals(401, again.server.items.size, "every item once")
        assertEquals(1, again.server.uploads.size, "the attached file once")
        assertEquals(false, inMemory, "the record was a file of this computer in the run that signed up")
        assertEquals(1, files.size, "$files")
    }

    @Test
    fun aRestoreStoppedHalfWayInTheRunOfTheFirstSignInOnAComputerGoesOnAfterANewStartAndStoresNothingTwice() {
        val elsewhere = world("made-elsewhere")
        elsewhere.api.lock()
        val w = started(elsewhere.server, elsewhere.instance, java.nio.file.Files.createTempDirectory("andvari-restore-first-sign-in").toFile())
        runBlocking { signIn(w.api, w.instance) }
        w.m.onSnapshot(w.api.snapshot)
        keepOn(w)
        val bytes = backup(401)
        stopAfter(w, bytes, taken = 1)
        assertEquals(200, w.server.items.size, "the first batch stored")
        val inMemory = w.api.restores.recordInMemoryOnly()
        val again = restart(w)
        goOn(again, bytes)
        assertEquals(401, again.server.items.size, "every item once")
        assertEquals(1, again.server.uploads.size, "the attached file once")
        assertEquals(false, inMemory, "the record was a file of this computer in the run that signed in")
    }

    // ---- a policy that forbids a copy arriving while a restore runs ----

    @Test
    fun aPolicyThatForbidsACopyArrivingWhileARestoreRunsOverACopyInMemoryLeavesNoFileAndTheRunGoesOnInMemory() {
        val w = world("policy-arrives")
        // An opening whose policy read answers late: the vault opens in memory (the switch is off at it), and the switch
        // is ticked afterwards, so the restore's record is a file while the vault is held in memory.
        val late = CompletableDeferred<Unit>()
        w.server.holdPolicy = late
        lockAndUnlock(w)
        keepOn(w)
        val bytes = backup(401)
        val f = flow(w, bytes)
        open(f)
        val line = ph(Placeholder.RESTORE_MEMORY_ONLY)
        assertFalse(line in page(w, f), "the record is a file: no line at the preview")
        var forbidden: Boolean? = null
        var drawn: List<String>? = null
        var filesAtSecond: List<File>? = null
        w.server.beforePush = { n ->
            when (n) {
                // The opening's read answers now, on another thread, and is waited for: the policy forbids a copy.
                1 -> {
                    w.server.offlineCacheAllowed = false
                    kotlin.concurrent.thread { late.complete(Unit) }.join()
                    forbidden = w.api.snapshot.account?.policy?.let { it.known && !it.offlineCacheAllowed }
                }
                2 -> {
                    drawn = page(w, f)
                    filesAtSecond = restoreFiles(w)
                }
            }
        }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(true, forbidden, "the policy was recorded during the run")
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage, "the run went on: ${f.views.value.stop}")
        assertEquals(401, w.server.items.size, "every item once")
        assertEquals(1, w.server.uploads.size, "the attached file once")
        assertEquals(emptyList(), filesAtSecond, "nothing of the restore written to the disk after the policy arrived")
        assertEquals(emptyList(), restoreFiles(w), "no file of the restore's records after the run")
        has(assertNotNull(drawn), line)
    }

    /**
     * The same policy over a vault whose copy is at rest (the app started again with the switch on): the policy's run
     * closes the vault. What the person sees then, and what choosing the file again stores, are written to the log.
     */
    @Test
    fun aPolicyThatForbidsACopyArrivingWhileARestoreRunsOverACopyAtRest() {
        val first = world("policy-arrives-at-rest")
        keepOn(first)
        first.api.lock()
        first.m.onSnapshot(first.api.snapshot)
        val w = started(first.server, first.instance, first.dir)
        val late = CompletableDeferred<Unit>()
        w.server.holdPolicy = late
        runBlocking { assertEquals(VaultUnlockResult.DONE, w.api.unlock(assertNotNull(w.api.snapshot.locked), strong)) }
        w.m.onSnapshot(w.api.snapshot)
        val bytes = backup(401)
        val f = flow(w, bytes)
        open(f)
        assertFalse(f.views.value.memoryOnly, "the record is a file")
        w.server.beforePush = { n ->
            if (n == 1) {
                w.server.offlineCacheAllowed = false
                kotlin.concurrent.thread { late.complete(Unit) }.join()
            }
        }
        // The desktop's work scope takes a closed vault's throw as a lock that overtook the work (Overtaken.launchOvertakable).
        val thrown = runCatching { runBlocking { f.confirm() } }.exceptionOrNull()
        println("AT-REST|thrown=$thrown")
        assertTrue(thrown == null || thrown is io.silencelen.andvari.core.crypto.KeysGoneException, "$thrown")
        w.server.beforePush = null
        w.m.onSnapshot(w.api.snapshot)
        val v = f.views.value
        println("AT-REST|stage=${v.stage} stop=${v.stop} noVault=${v.noVault} memoryOnly=${v.memoryOnly} items=${w.server.items.size} uploads=${w.server.uploads.size}")
        println("AT-REST|drawn=${page(w, f)}")
        println("AT-REST|files=${restoreFiles(w).map { it.name }} phase=${w.api.snapshot.phase} content=${w.m.content.value != null} restoring=${w.m.restoring.value != null}")
        assertEquals(emptyList(), restoreFiles(w), "no file of the restore's records after the policy's run")
        val c = w.m.content.value
        if (c != null) {
            val again = flow(w, bytes)
            open(again)
            println("AT-REST|again preview=${again.views.value.stage} noVault=${again.views.value.noVault} memoryOnly=${again.views.value.memoryOnly} lines=${page(w, again)}")
            runBlocking { again.confirm() }
            println("AT-REST|again stage=${again.views.value.stage} stop=${again.views.value.stop} items=${w.server.items.size} uploads=${w.server.uploads.size}")
        }
    }

    // ---- the line when it becomes true during a run ----

    @Test
    fun theSwitchTurnedOffDuringARunDrawsTheLineAndTurnedOnAgainTakesItAwayAndTheRecordIsAFileAgain() {
        val w = world("switch-during-run")
        keepOn(w)
        val bytes = backup(601)
        val f = flow(w, bytes)
        open(f)
        val line = ph(Placeholder.RESTORE_MEMORY_ONLY)
        assertFalse(line in page(w, f), "a file: no line at the preview")
        var off: List<String>? = null
        var filesWhileOff: List<File>? = null
        var on: List<String>? = null
        w.server.beforePush = { n ->
            when (n) {
                1 -> w.m.setKeepSignIn(false)
                2 -> {
                    off = page(w, f)
                    filesWhileOff = restoreFiles(w)
                    w.m.setKeepSignIn(true)
                    w.m.answerNoKeyStore(true)
                }
                3 -> {
                    on = page(w, f)
                    w.server.failNext = 503
                }
            }
        }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        assertEquals(400, w.server.items.size, "two batches stored")
        has(assertNotNull(off), line)
        assertEquals(emptyList(), filesWhileOff, "switched off: the record goes on in memory")
        assertFalse(line in assertNotNull(on), "switched on again: the line goes: $on")
        assertFalse(line in page(w, f), "nor is it drawn at the stop")
        assertEquals(1, restoreFiles(w).size, "a file again")
        val again = restart(w)
        goOn(again, bytes)
        assertEquals(601, again.server.items.size, "every item once")
        assertEquals(1, again.server.uploads.size, "the attached file once")
    }

    @Test
    fun theLineFollowsTheSwitchWhileThePreviewIsShown() {
        val w = world("switch-at-preview")
        keepOn(w)
        val f = flow(w, small())
        open(f)
        val line = ph(Placeholder.RESTORE_MEMORY_ONLY)
        assertFalse(line in page(w, f))
        w.m.setKeepSignIn(false)
        has(page(w, f), line)
        keepOn(w)
        assertFalse(line in page(w, f))
    }

    // ---- nothing of it on the phone ----

    @Test
    fun onlyTheDesktopsInterfaceHandsOutARestoreAndThePhoneHasNone() {
        // Every type the phone's interface reaches through the return types of its members, four steps deep (the
        // interface's parts, their parts, …), not its direct members alone.
        val seen = HashSet<Class<*>>()
        var edge = listOf<Class<*>>(AppApi::class.java)
        repeat(4) {
            edge = edge.filter { seen.add(it) }.flatMap { c -> c.methods.map { it.returnType } }.filter { it.name.startsWith("io.silencelen.andvari.") && it !in seen }.distinct()
        }
        seen += edge
        assertTrue(seen.size > 10, "the walk reached the interface's parts: ${seen.size}")
        assertFalse(BackupRestoreApi::class.java in seen, "the phone's interface reaches no restore")
        assertTrue(DesktopAppApi::class.java.methods.any { it.returnType == BackupRestoreApi::class.java })
        val sources = File("../app-android/src")
        assertTrue(sources.isDirectory, "the phone's sources are where the scan looks: ${sources.absolutePath}")
        val android = sources.walkTopDown().filter { it.isFile && it.extension == "kt" }.filter { "BackupRestore" in it.readText() }.toList()
        assertEquals(emptyList(), android, "no screen of the phone reaches the restore")
    }
}
