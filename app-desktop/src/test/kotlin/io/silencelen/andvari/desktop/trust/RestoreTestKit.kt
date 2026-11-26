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
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
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
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.jetbrains.skia.Surface as SkiaSurface
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What the restore's tests share: the shared code's REAL engine and restore over this computer's real stores, against
 * the shared code's test server with an item plane in front of it, real backup files made by the shared code's own
 * `Backup.build`, and the restore's page drawn as the window draws it.
 */
internal abstract class RestoreTestKit {
    protected val crypto = createCryptoProvider()
    protected val strong = "correct horse Battery 9 staple"
    protected val pass = "a backup passphrase for the test"

    /**
     * The test server with an item plane: the personal vault's row, each change taken once by its id (a change sent again
     * under the same id is answered as taken), attached files taken. While [rejectFirst] the first change of the next
     * push is refused for good (`item_too_large`), and again whenever it comes back. [failNext] answers the next push
     * with a refusal of the whole push (that status, with [failCode]). [beforePush] sees every push before it is
     * answered, numbered from when it was set; what it throws is thrown out of the network call.
     */
    class KitServer(private val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var quota: QuotaUse? = null
        var offlineCacheAllowed = true
        var rejectFirst = false
        private var rejected: String? = null
        var failNext: Int? = null
        var failCode = "server_error"

        /** Every call but the policy's is refused with this status and code while set (the server ended the session, an update). */
        var refuseAll: Pair<Int, String>? = null
        var pushes = 0
        var rev = 1L
        val items = ArrayList<SyncItem>()
        val taken = LinkedHashSet<String>()
        val uploads = ArrayList<String>()

        /** The changes each push carried, by item id, in the order sent. */
        val sent = ArrayList<List<String>>()
        private var pushCalls = 0
        var beforePush: ((Int) -> Unit)? = null
            set(value) {
                pushCalls = 0
                field = value
            }
        var holdPolicy: CompletableDeferred<Unit>? = null

        /** The next push is taken whole, and its answer is lost: the client sees a refusal of the whole push. */
        var loseNextAnswer = false

        /** Called once at the first sync after a push in which the server refused a change for good. */
        var syncAfterRefusal: (() -> Unit)? = null
        private var refusedInPush = false

        /** While set, every vault's creation is asked to wait this many seconds (`rate_limited`), as the server paces it. */
        var vaultCreationWait: Long? = null

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            val refused = refuseAll
            if (refused != null && route != WireRoute.CLIENT_POLICY) return WireResult.Refused(refused.first, WireError(refused.second, "test"))
            val wait = vaultCreationWait
            if (wait != null && route == WireRoute.LOG_APPEND) return WireResult.Refused(429, WireError("rate_limited", "test"), wait)
            return when (route) {
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
                    if (refusedInPush) {
                        refusedInPush = false
                        syncAfterRefusal?.let { hook ->
                            syncAfterRefusal = null
                            hook()
                        }
                    }
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since && it.vaultId == pv }, emptyList(), emptyList(), 0, 0, quota = quota)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    beforePush?.invoke(++pushCalls)
                    val fail = failNext
                    if (fail != null) {
                        failNext = null
                        WireResult.Refused(fail, WireError(failCode, "test"))
                    } else {
                        pushes++
                        val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                        sent += b.mutations.map { it.itemId }
                        if (rejectFirst && rejected == null) rejected = b.mutations.first().mutationId
                        val reject = if (rejectFirst) rejected else null
                        val results = b.mutations.map { m ->
                            if (m.mutationId == reject) {
                                refusedInPush = true
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
                        if (loseNextAnswer) {
                            // Taken, and the answer lost on the way back.
                            loseNextAnswer = false
                            WireResult.Refused(503, WireError("server_error", "test"))
                        } else {
                            WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                        }
                    }
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
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

    class World(val server: KitServer, val api: EngineDesktopAppApi, val m: TrustModel, val home: DesktopHome, val dir: File, val instance: FakeInstance)

    protected fun newDir(name: String): File = java.nio.file.Files.createTempDirectory("andvari-restore-kit-$name").toFile()

    /** Alice signed up in a new folder; [offlineCacheAllowed]: what the server's policy says of an offline copy. */
    protected fun world(name: String, offlineCacheAllowed: Boolean = true): World {
        val instance = FakeInstance(crypto)
        val server = KitServer(instance)
        server.offlineCacheAllowed = offlineCacheAllowed
        val w = started(server, instance, newDir(name))
        runBlocking { signUp(w.api, instance) }
        w.m.onSnapshot(w.api.snapshot)
        return w
    }

    /** The app started over [dir]: a new home, engine and model, nothing of an earlier run in memory. */
    protected fun started(server: KitServer, instance: FakeInstance, dir: File): World {
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

    protected inline fun <reified T : EntryScreen> DesktopAppApi.at(): T = snapshot.entry as T

    protected suspend fun signUp(a: DesktopAppApi, instance: FakeInstance, email: String = "alice@example.com") {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), instance.origin.removePrefix("https://")))
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

    protected suspend fun signIn(a: DesktopAppApi, instance: FakeInstance) {
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), instance.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, a.entry.submitSignIn(a.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /** A sign-out as the person confirms it (with the second confirmation where the app asks for one). */
    protected fun signOut(w: World) {
        runBlocking {
            if (w.api.signOut() == PlainResult.UNSENT_NOT_CONFIRMED) w.api.signOutConfirmed(assertNotNull(w.api.signOutCheck()))
        }
        w.m.onSnapshot(w.api.snapshot)
    }

    // ---- the backup files, made by the shared code's own writer ----

    protected fun id() = Bytes.uuidV4FromBytes(crypto.randomBytes(16))

    protected fun doc(name: String, attachments: List<AttachmentRef> = emptyList()) =
        ItemDoc(type = "login", name = name, login = LoginData(username = "me", password = "pw-$name", uris = listOf("https://example.test")), attachments = attachments)

    protected val personal = BackupVault("11111111-1111-4111-8111-111111111111", "personal", "Personal", "owner")
    protected val family = BackupVault("22222222-2222-4222-8222-222222222222", "shared", "Family", "owner")

    /**
     * A backup of [items] personal items ("A" first, with one attached file of 70 000 bytes) and [familyItems] items of
     * the shared vault "Family" (owned).
     */
    protected fun backup(items: Int, familyItems: Int = 2, fileId: String = id()): ByteArray {
        val fileKey = crypto.randomBytes(32)
        val attachmentId = id()
        val plain = ByteArray(70_000) { (it % 251).toByte() }
        val first = BackupItem(id(), personal.vaultId, 1, 0, doc("A", listOf(AttachmentRef(attachmentId, "scan.pdf", plain.size.toLong(), Bytes.toB64(fileKey)))))
        val rest = (2..items).map { BackupItem(id(), personal.vaultId, 1, 0, doc("Item $it")) }
        val shared = (1..familyItems).map { BackupItem(id(), family.vaultId, 1, 0, doc("Family $it")) }
        val payload = BackupPayload(
            exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal, family),
            items = listOf(first) + rest + shared,
            attachments = listOf(BackupAttachmentEntry(1, attachmentId, first.itemId, "scan.pdf", plain.size.toLong(), Bytes.toB64(fileKey))),
        )
        val out = ByteArrayOutputStream()
        Backup.build(crypto, pass, fileId, crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload, listOf(Backup.AttachmentSection(fileKey) { plain.copyOf() })) { out.write(it) }
        return out.toByteArray()
    }

    // ---- drawing ----

    /** [content] drawn in a window of the desktop's width; [lines] are the texts on it, top to bottom. */
    @OptIn(InternalComposeUiApi::class)
    class Drawn(content: @Composable () -> Unit) {
        private val owners = LinkedHashSet<SemanticsOwner>()
        private val surface = SkiaSurface.makeRasterN32Premul(900, 4000)
        private var t = 0L
        private val scene = CanvasLayersComposeScene(
            Density(1f), LayoutDirection.Ltr, IntSize(900, 4000), Dispatchers.Unconfined,
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

        /** Whether the control that shows [text] is drawn disabled (null when no such text is drawn). */
        fun disabled(text: String): Boolean? {
            lines()
            val node = owners.toList().flatMap { it.getAllSemanticsNodes(mergingEnabled = false) }.firstOrNull { textOf(it) == text } ?: return null
            var n: SemanticsNode? = node
            while (n != null) {
                if (n.config.contains(SemanticsProperties.Disabled)) return true
                n = n.parent
            }
            return false
        }

        private fun node(text: String): SemanticsNode? {
            lines()
            return owners.toList().flatMap { it.getAllSemanticsNodes(mergingEnabled = false) }.firstOrNull { textOf(it) == text }
        }

        /** The tick box [text] is drawn in: true or false as it is ticked, null when the text is drawn in none (or not drawn). */
        fun ticked(text: String): Boolean? {
            var n: SemanticsNode? = node(text) ?: return null
            while (n != null) {
                n.config.getOrNull(SemanticsProperties.ToggleableState)?.let { return it == androidx.compose.ui.state.ToggleableState.On }
                n = n.parent
            }
            return null
        }

        /** Presses what draws [text], as a click on it does (its nearest node that takes a click); false when nothing does. */
        fun press(text: String): Boolean {
            var n: SemanticsNode? = node(text) ?: return false
            while (n != null) {
                val click = n.config.getOrNull(androidx.compose.ui.semantics.SemanticsActions.OnClick)
                if (click != null) return click.action?.invoke() ?: false
                n = n.parent
            }
            return false
        }

        private fun textOf(n: SemanticsNode): String? =
            (n.config.getOrNull(SemanticsProperties.Text).orEmpty() + listOfNotNull(n.config.getOrNull(SemanticsProperties.EditableText)))
                .joinToString(" ") { it.text }.takeIf { it.isNotBlank() }
    }

    protected fun drawn(content: @Composable () -> Unit): List<String> {
        val d = Drawn(content)
        try {
            return d.lines()
        } finally {
            d.close()
        }
    }

    protected fun page(w: World, flow: RestoreFlow): List<String> = drawn { RestorePage(w.m, flow) }

    /** The restore's page of [flow] drawn and kept, to find its tick boxes and buttons and press them; closed after [block]. */
    protected fun <T> onScreen(w: World, flow: RestoreFlow, block: (Drawn) -> T): T {
        val d = Drawn { RestorePage(w.m, flow) }
        try {
            return block(d)
        } finally {
            d.close()
        }
    }

    /** Waits (at most 20 s) until [what] holds: a press launches its work in the page's scope. */
    protected fun until(what: () -> Boolean): Boolean {
        val end = System.currentTimeMillis() + 20_000
        while (System.currentTimeMillis() < end) {
            if (what()) return true
            Thread.sleep(20)
        }
        return what()
    }

    /** The question before a sign-out, as drawn. */
    protected fun question(w: World): List<String> = drawn { SignOutQuestion(w.m, null, w.api.snapshot) {} }

    /** A backup of [payload] under [pass], with [parts] its attached files' parts (key, plain bytes). */
    protected fun build(payload: BackupPayload, parts: List<Pair<ByteArray, ByteArray>> = emptyList()): ByteArray {
        val out = ByteArrayOutputStream()
        Backup.build(crypto, pass, id(), crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload, parts.map { (k, p) -> Backup.AttachmentSection(k) { p.copyOf() } }) { out.write(it) }
        return out.toByteArray()
    }

    /** [n] personal items without the files they name: the items numbered in [named] each name one; item 1 is "A". */
    protected fun withoutFiles(n: Int, named: Set<Int>): ByteArray = build(
        BackupPayload(
            exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal),
            items = (1..n).map { k ->
                val refs = if (k in named) listOf(AttachmentRef(id(), "f$k.pdf", 10, Bytes.toB64(crypto.randomBytes(32)))) else emptyList()
                BackupItem(id(), personal.vaultId, 1, 0, doc(if (k == 1) "A" else "Item $k", refs))
            },
        ),
    )

    protected fun ph(p: Placeholder, vararg args: String) = UiText.ph(p, *args).shown()

    protected fun has(lines: List<String>, vararg expected: String) {
        for (e in expected) assertTrue(e in lines, "drawn: \"$e\" in $lines")
    }

    /** The number the restore button names as drawn ("Restore 412 items"), or null when no such button is drawn. */
    protected fun buttonCount(lines: List<String>): Int? = lines.firstNotNullOfOrNull { Regex("^Restore (\\d+) items$").find(it)?.groupValues?.get(1)?.toInt() }

    protected fun flow(w: World, bytes: ByteArray, name: String = "family.andvari"): RestoreFlow {
        val c = assertNotNull(w.m.content.value, "the vault is open")
        w.m.openRestore(c, name, bytes)
        return assertNotNull(w.m.restoring.value)
    }

    protected fun open(f: RestoreFlow, passphrase: String = pass) = runBlocking { f.open(passphrase.toCharArray()) }

    /** The files of restore records in [w]'s folder. */
    protected fun restoreFiles(w: World): List<File> = w.dir.walkTopDown().filter { it.isFile && ContentStores.RESTORES in it.name }.toList()

    /** The items the server holds in the account's personal vault. */
    protected fun personalItems(w: World): Int {
        val pv = w.instance.accounts.values.first().personalWrap?.vaultId
        return w.server.items.count { it.vaultId == pv }
    }

    /** "Keep me signed in" ticked as the person ticks it. */
    protected fun keepOn(w: World) {
        w.m.setKeepSignIn(true)
        w.m.answerNoKeyStore(true)
        assertTrue(w.home.keepsAtRest())
    }

    protected fun lock(w: World) {
        w.api.lock()
        w.m.onSnapshot(w.api.snapshot)
    }

    protected fun unlock(w: World) {
        runBlocking { assertEquals(VaultUnlockResult.DONE, w.api.unlock(assertNotNull(w.api.snapshot.locked), strong)) }
        w.m.onSnapshot(w.api.snapshot)
    }

    /** [w] locked, then the app started again over its folder and unlocked: nothing of the earlier run in memory. */
    protected fun restart(w: World): World {
        lock(w)
        val again = started(w.server, w.instance, w.dir)
        unlock(again)
        return again
    }

    /** A world whose app was started again with "Keep me signed in" on: the vault's copy and the record at rest. */
    protected fun atRest(name: String): World {
        val first = world(name)
        keepOn(first)
        return restart(first)
    }

    /** [w]'s restore of [bytes] (its personal vault), stopped by a refused push once [taken] pushes were taken. */
    protected fun stopAfter(w: World, bytes: ByteArray, taken: Int): RestoreFlow {
        val f = flow(w, bytes)
        open(f)
        w.server.beforePush = { n -> if (n == taken + 1) w.server.failNext = 503 }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        return f
    }

    /** [block], and what it threw (the desktop's work scope takes a throw as the lock or a fault). */
    protected fun caught(block: suspend () -> Unit): Throwable? = runCatching { runBlocking { block() } }.exceptionOrNull()
}
