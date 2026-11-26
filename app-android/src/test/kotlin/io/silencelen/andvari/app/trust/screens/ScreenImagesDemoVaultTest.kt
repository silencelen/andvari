package io.silencelen.andvari.app.trust.screens

import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.node.RootForTest
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.SemanticsOwner
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes
import androidx.compose.ui.semantics.getOrNull
import androidx.core.app.ActivityOptionsCompat
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import app.cash.paparazzi.SnapshotHandler
import app.cash.paparazzi.detectEnvironment
import com.android.resources.NightMode
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.trust.BuildConstants
import io.silencelen.andvari.app.trust.FirstVaultView
import io.silencelen.andvari.app.trust.LocalDrawnAsk
import io.silencelen.andvari.app.trust.LocalFirstPage
import io.silencelen.andvari.app.trust.LocalFirstSharingVault
import io.silencelen.andvari.app.trust.LocalFirstVaultView
import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.SignedInPage
import io.silencelen.andvari.app.trust.TrustApp
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.ItemCheck
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.lang.reflect.Proxy

/**
 * Pictures of the phone app holding one believable vault, for the product's store pages and website: Jordan's account
 * (`jordan@example.com`) with a personal vault and a shared "Home" vault Jordan owns, Alex a writer and Sam a reader
 * of it. Drawn from the fake app interface (the same stand-in the other unit tests use), with no server and no phone.
 * Every password, code secret and card number in it is made up; the card's number is the one published for testing.
 *
 * Run on request only, as [ScreenImagesTest] is (the build leaves both out otherwise):
 * `gradle-locked.sh --offline :app-android:testDebugUnitTest -PandvariScreens --tests '*ScreenImagesDemoVaultTest'`.
 * The pictures land in `app-android/build/android-screens/demo/<dark|light>/<n>-<shot>.png`, 1080 × 2400 pixels (a
 * Pixel 6 at its own resolution). Beside each, `<n>-<shot>.lines.tsv` lists every line of text inside the picture, and
 * marks the lines that still show a placeholder (`⟦…⟧`) with the key they stand for; `awaiting.tsv` gathers those.
 */
class ScreenImagesDemoVaultTest {
    private val outDir: File = File(System.getProperty("andvari.screens.dir") ?: "build/android-screens", "demo")

    private var target: File? = null

    /** Writes the frame to [target]; the same reflection as [ScreenDrawing]'s writer (the compile classpath has no AWT). */
    private val writer: SnapshotHandler = run {
        val loader = SnapshotHandler::class.java.classLoader
        fun objectMethod(proxy: Any, name: String, args: Array<out Any?>?): Any? = when (name) {
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.get(0)
            "toString" -> "ScreenImagesDemoVaultTest.writer"
            else -> null
        }
        Proxy.newProxyInstance(loader, arrayOf(SnapshotHandler::class.java)) { proxy, method, args ->
            if (method.name != "newFrameHandler") return@newProxyInstance objectMethod(proxy, method.name, args)
            Proxy.newProxyInstance(loader, arrayOf(SnapshotHandler.FrameHandler::class.java)) { frame, m, a ->
                if (m.name != "handle") return@newProxyInstance objectMethod(frame, m.name, a)
                val f = requireNotNull(target)
                f.parentFile.mkdirs()
                val rendered = Class.forName("java.awt.image.RenderedImage")
                Class.forName("javax.imageio.ImageIO").getMethod("write", rendered, String::class.java, File::class.java)
                    .invoke(null, a[0], "png", f)
                null
            }
        } as SnapshotHandler
    }

    @get:Rule
    val paparazzi = Paparazzi(
        environment = detectEnvironment().copy(compileSdkVersion = DRAWN_AT_API),
        deviceConfig = PHONE,
        snapshotHandler = writer,
        supportsRtl = true,
        useDeviceResolution = true,
    )

    @Test fun dark() = drawAll(dark = true)

    @Test fun light() = drawAll(dark = false)

    private fun drawAll(dark: Boolean) {
        val theme = if (dark) "dark" else "light"
        paparazzi.unsafeUpdateConfig(deviceConfig = PHONE.copy(nightMode = if (dark) NightMode.NIGHT else NightMode.NOTNIGHT))
        val failed = mutableListOf<String>()
        val awaiting = StringBuilder()
        for (shot in DemoShots.all) {
            try {
                val d = shot.make()
                var lines: List<TextLine> = emptyList()
                target = File(outDir, "$theme/${shot.name}.png")
                paparazzi.snapshot(name = shot.name) {
                    val view = LocalView.current
                    CompositionLocalProvider(
                        LocalDrawnAsk provides null,
                        LocalFirstPage provides d.page,
                        LocalFirstSharingVault provides d.sharingVault,
                        LocalFirstVaultView provides d.view,
                        LocalActivityResultRegistryOwner provides NothingLaunched,
                    ) {
                        AndvariTheme {
                            Box(
                                Modifier.fillMaxSize().drawWithContent {
                                    drawContent()
                                    (view as? RootForTest)?.let { lines = textLines(it.semanticsOwner, size.height) }
                                },
                            ) { TrustApp(d.model) }
                        }
                    }
                }
                File(outDir, "$theme/${shot.name}.lines.tsv").writeText(lines.joinToString("") { it.row() })
                for (l in lines.filter { it.awaiting }) awaiting.append(shot.name).append('\t').append(l.row())
            } catch (t: Throwable) {
                failed += "${shot.name}\t${t.javaClass.name}: ${t.message?.lineSequence()?.firstOrNull()}"
            }
        }
        File(outDir, "$theme/awaiting.tsv").writeText(awaiting.toString())
        File(outDir, "$theme/failed.tsv").writeText(failed.joinToString("") { "$it\n" })
        check(failed.isEmpty()) { "pictures not drawn: $failed" }
    }

    private companion object {
        /** A Pixel 6: 1080 × 2400 pixels, 411 dp wide. */
        val PHONE: DeviceConfig = DeviceConfig.PIXEL_6
    }
}

/** One line of text inside a picture, with the keys of the placeholder it shows (none: it has its words). */
internal class TextLine(val text: String, val top: Int, val keys: List<String>) {
    val awaiting: Boolean get() = "⟦" in text

    fun row(): String = "$top\t${if (awaiting) "AWAITING ${keys.ifEmpty { listOf("(no key found)") }.joinToString(" ")}" else "final"}\t${text.replace('\n', ' ')}\n"
}

/** Every text drawn inside the visible [heightPx] of the window, top to bottom. */
private fun textLines(owner: SemanticsOwner, heightPx: Float): List<TextLine> =
    owner.getAllSemanticsNodes(mergingEnabled = false).mapNotNull { node ->
        val b = node.boundsInRoot
        if (b.width <= 0f || b.height <= 0f || b.top >= heightPx || b.bottom <= 0f) return@mapNotNull null
        val text = (node.config.getOrNull(SemanticsProperties.Text).orEmpty() + listOfNotNull(node.config.getOrNull(SemanticsProperties.EditableText)))
            .joinToString(" ") { it.text }.takeIf { it.isNotBlank() } ?: return@mapNotNull null
        TextLine(text, b.top.toInt(), placeholderKeys(text))
    }.sortedBy { it.top }

/**
 * The keys a placeholder's text stands for: the app's own [Placeholder] whose gloss it shows, a reserved [CopyKey] whose
 * name it carries, or a [CopyKey] awaiting its words whose fixed parts it holds. For the report only; nothing asserts it.
 */
internal fun placeholderKeys(text: String): List<String> {
    if ("⟦" !in text) return emptyList()
    val out = ArrayList<String>()
    val generic = setOf(Placeholder.RESERVED_COPY, Placeholder.AWAITING_OWNER)
    for (p in Placeholder.entries) {
        if (p.words != null || p in generic) continue
        if ("⟦${p.gloss}⟧" in text || "⟦${p.gloss}: " in text) out += "Placeholder.${p.name}"
    }
    val reserved = "⟦${Placeholder.RESERVED_COPY.gloss}: "
    for (k in CopyKey.entries) if (k.reserved && "$reserved${k.name}" in text) out += "CopyKey.${k.name}"
    val bare = text.replace("⟦", "").replace("⟧", "")
    for (k in CopyKey.entries) {
        if (!k.awaitingOwner) continue
        val parts = k.english.split(Regex("\\{\\d+\\}")).map { it.replace("⟦", "").replace("⟧", "").trim() }.filter { it.length >= 4 }
        if (parts.isNotEmpty() && parts.all { it in bare }) out += "CopyKey.${k.name}"
    }
    return out
}

/** The file pickers register for a result; in a picture nothing is ever launched. */
private object NothingLaunched : ActivityResultRegistryOwner {
    override val activityResultRegistry: ActivityResultRegistry = object : ActivityResultRegistry() {
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {}
    }
}

/** What a picture draws: the model, the page it opens on, the vault view and the shared vault's page. */
internal class DemoDrawn(
    val model: TrustModel,
    val page: SignedInPage? = null,
    val view: FirstVaultView? = null,
    val sharingVault: String? = null,
)

internal class DemoShot(val name: String, val make: () -> DemoDrawn)

/** The pictures, in the order of the store pages. */
internal object DemoShots {
    private fun model(api: FakeAppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also { it.onSnapshot(api.snapshot) }

    /** The demo vault, signed in and open, with [prep] done on it. */
    private fun demo(samShares: Boolean = true, prep: (DemoVault.Built, TrustModel) -> DemoDrawn): () -> DemoDrawn = {
        val api = FakeAppApi(AppPlatform.ANDROID, null)
        val built = DemoVault.build(api, samShares)
        val m = model(api)
        prep(built, m).also { m.onSnapshot(api.snapshot) }
    }

    val all: List<DemoShot> = listOf(
        // 1. The first run with its ways to start: no account yet.
        DemoShot("1-first-run") {
            val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN)
            DemoDrawn(model(api))
        },
        // 2. The vault list: both vaults' items.
        DemoShot("2-vault-list", demo { _, m -> DemoDrawn(m, SignedInPage.VAULT) }),
        // 3. The GitHub login opened: its one-time code on show.
        DemoShot("3-github-one-time-code", demo { b, m -> DemoDrawn(m, SignedInPage.VAULT, FirstVaultView(open = b.itemId("GitHub"))) }),
        // 4. Password health: the reused pair and the weak password.
        DemoShot("4-password-health", demo { b, m ->
            b.content.openHealth()
            DemoDrawn(m, SignedInPage.VAULT)
        }),
        // 5. The Home vault's members with their roles.
        DemoShot("5-home-members", demo { b, m ->
            val home = requireNotNull(b.api.snapshot.account).vaults.first { it.name == DemoVault.HOME }
            runBlocking { b.api.vaults.openMembers(home) }
            DemoDrawn(m, SignedInPage.SHARING)
        }),
        // 6. Comparing codes with Sam before the Home vault is shared with Sam.
        DemoShot("6-compare-codes", demo(samShares = false) { b, m ->
            runBlocking {
                b.api.contacts.openContacts()
                val sam = requireNotNull(b.api.snapshot.account?.contacts).contacts.first { it.label == "Sam" }
                b.api.contacts.openCompare(sam)
            }
            DemoDrawn(m, SignedInPage.SHARING)
        }),
        // 7. The encrypted backup file, opened from Settings: what goes into it.
        DemoShot("7-export-backup", demo { b, m ->
            runBlocking { b.content.openExport(ExportKind.BACKUP) }
            DemoDrawn(m, SignedInPage.SETTINGS)
        }),
    )
}

/**
 * The demo vault, given to the fake app interface through what it offers: an account on its public server, two contacts,
 * a shared vault with its members, and the items seeded as the vault content stores them (so a login's "last checked"
 * and its one-time code are set as a saved item holds them). The desktop's pictures build the same vault.
 */
internal object DemoVault {
    const val EMAIL = "jordan@example.com"
    const val HOME = "Home"
    private const val PASSWORD = "a made-up master password for the demo"
    private const val DAY = 86_400_000L

    /** The password Amazon and Spotify share: password health shows them as one reused pair. */
    private const val SHARED = "Demo-Shared-Pinecone-Harbor-24"

    class Built(val api: FakeAppApi, val content: FakeVaultContent, val homeId: String) {
        fun itemId(name: String): String = content.state.items.first { it.name == name }.itemId
    }

    /** [samShares]: Sam is a reader of Home, compared; false: Sam is a contact whose codes are ready to compare. */
    fun build(api: FakeAppApi, samShares: Boolean = true): Built {
        val me = api.script.publicInstance.addAccount(EMAIL, PASSWORD)
        me.nameHere = "Jordan"
        val alex = me.addContact("Alex", compared = true)
        val sam = me.addContact("Sam", compared = samShares)
        if (!samShares) {
            sam.codesReady = true
            sam.code = "305618"
        }
        val home = me.addVault(HOME, RoleInVault.OWNER)
        home.addMember("Alex", RoleInVault.WRITER, alex)
        if (samShares) home.addMember("Sam", RoleInVault.READER, sam)
        home.itemCount = 3
        api.script.signedInAs(me)
        val c = requireNotNull(api.fakeContent) { "the vault did not open" }
        c.addSharedVault(home.vaultId, HOME, VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val personal = FakeVaultContent.PERSONAL_VAULT_ID
        val now = 1_800_000_000_000L

        fun login(vault: String, name: String, user: String, password: String, uri: String, changedDaysAgo: Int, checkedDaysAgo: Int?, totp: String? = null, favorite: Boolean = false) {
            val check = checkedDaysAgo?.let { ItemCheck(at = now - it * DAY, result = "ok", okAt = now - it * DAY) }
            val id = c.seed(vault, ItemDoc(type = "login", name = name, favorite = favorite, login = LoginData(username = user, password = password, uris = listOf(uri), totp = totp), check = check))
            c.setUpdatedAt(id, now - changedDaysAgo * DAY)
        }
        login(personal, "Google", EMAIL, "Demo-Google-Lantern-Quartz-58", "https://accounts.google.com", 210, 14, favorite = true)
        login(personal, "Amazon", EMAIL, SHARED, "https://www.amazon.com", 720, 430)
        login(personal, "Spotify", EMAIL, SHARED, "https://accounts.spotify.com", 500, 250)
        login(personal, "GitHub", "jordan-example", "Demo-GitHub-Copper-Meadow-71", "https://github.com", 95, 21, totp = "DEMODEMODEMODEMO")
        login(personal, "PayPal", EMAIL, "paypal123", "https://www.paypal.com", 900, null)
        login(home.vaultId, "Netflix", "home@example.com", "Demo-Home-Movie-Night-33", "https://www.netflix.com", 300, 40)
        login(home.vaultId, "Disney+", "home@example.com", "Demo-Home-Castle-Rocket-19", "https://www.disneyplus.com", 160, 33)
        fun ok(r: ActionResult) = check(r == ActionResult.Ok) { "the fake refused a save: $r" }
        runBlocking {
            ok(c.saveCard(null, CardInput("Everyday Visa", "Jordan", "4242424242424242", "08", "29", "", "", "", false), personal))
            ok(c.saveNote(null, NoteInput("Home Wi-Fi", "Network: JordanHome-Demo\nPassword: Demo-Wifi-Maple-Otter-40", false), personal))
            ok(c.saveNote(null, NoteInput("Alarm code", "Demo code: 0000 (not a real code)", false), home.vaultId))
        }
        val built = Built(api, c, home.vaultId)
        c.setUpdatedAt(built.itemId("Everyday Visa"), now - 60 * DAY)
        c.setUpdatedAt(built.itemId("Home Wi-Fi"), now - 400 * DAY)
        c.setUpdatedAt(built.itemId("Alarm code"), now - 120 * DAY)
        // Synced once in the background, as the app does after the vault opens: no "not synced yet" line above the list.
        ok(runBlocking { c.syncQuietly() })
        return built
    }
}
