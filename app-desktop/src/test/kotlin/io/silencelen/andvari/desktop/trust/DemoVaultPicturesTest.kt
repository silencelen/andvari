package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.InternalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asComposeCanvas
import androidx.compose.ui.platform.PlatformContext
import androidx.compose.ui.scene.CanvasLayersComposeScene
import androidx.compose.ui.scene.ComposeSceneContext
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsOwner
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.client.ItemCheck
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.desktop.AndvariDesktopTheme
import io.silencelen.andvari.desktop.ThemeMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.jetbrains.skia.EncodedImageFormat
import org.jetbrains.skia.Surface as SkiaSurface
import java.io.File
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Pictures of the desktop's vault window holding one believable vault, for the product's store pages and website:
 * Jordan's account (`jordan@example.com`) with a personal vault and a shared "Home" vault, drawn from the fake app
 * interface with no server, in the dark theme at 1600 × 1000 pixels. The desktop shows an opened item in place of the
 * list, so the window is drawn twice: the list, then the Google login opened from its row.
 *
 * Every test run draws them: `app-desktop/build/desktop-screens/demo/8-vault-list.png` and `8-google-login.png`, each with
 * `<name>.lines.tsv` beside it listing every line of text in the picture, the lines still showing a placeholder (`⟦…⟧`)
 * marked with the key they stand for. Every password, code secret and card number in the vault is made up.
 */
class DemoVaultPicturesTest {
    private val outDir = File(System.getProperty("andvari.screens.dir") ?: "build/desktop-screens", "demo")

    @OptIn(InternalComposeUiApi::class)
    @Test
    fun theVaultWindowShowsTheDemoVaultAndOpensTheGoogleLoginFromItsRow() {
        val api = FakeDesktopAppApi()
        DemoVault.build(api)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
        // The scene ImageComposeScene builds, with a platform that tells which semantics owners the window has, so the
        // test can read the lines drawn and open a row as a click does.
        val owners = LinkedHashSet<SemanticsOwner>()
        val platform = object : PlatformContext by PlatformContext.Empty {
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
        val scene = CanvasLayersComposeScene(
            Density(1f),
            LayoutDirection.Ltr,
            IntSize(WIDTH, HEIGHT),
            Dispatchers.Unconfined,
            object : ComposeSceneContext {
                override val platformContext: PlatformContext = platform
            },
            {},
        )
        scene.setContent {
            AndvariDesktopTheme(ThemeMode.Dark) { Surface { Column(Modifier.fillMaxSize()) { TrustApp(m, null, "log") } } }
        }
        val surface = SkiaSurface.makeRasterN32Premul(WIDTH, HEIGHT)
        var t = 0L
        fun nodes(merged: Boolean): List<SemanticsNode> = owners.toList().flatMap { it.getAllSemanticsNodes(mergingEnabled = merged) }
        fun draw(name: String): List<String> {
            repeat(4) {
                t += 50_000_000L
                surface.canvas.clear(0)
                scene.render(surface.canvas.asComposeCanvas(), t)
            }
            outDir.mkdirs()
            File(outDir, "$name.png").writeBytes(assertNotNull(surface.makeImageSnapshot().encodeToData(EncodedImageFormat.PNG)).bytes)
            val lines = nodes(merged = false)
                .filter { it.boundsInRoot.let { b -> b.width > 0f && b.height > 0f && b.top < HEIGHT && b.bottom > 0f } }
                .mapNotNull { n -> textOf(n)?.let { n.boundsInRoot.top.toInt() to it } }
                .sortedBy { it.first }
            File(outDir, "$name.lines.tsv").writeText(lines.joinToString("") { (top, text) -> row(top, text) })
            return lines.map { it.second }
        }
        try {
            val list = draw("8-vault-list")
            // The items by name, as far as the window's height reaches.
            for (name in listOf("Alarm code", "Amazon", "Disney+", "Everyday Visa", "GitHub", "Google", "Home Wi-Fi", "Netflix")) {
                assertTrue(list.any { it == name }, "the list shows $name: $list")
            }
            val row = nodes(merged = true)
                .first { n -> n.config.getOrNull(SemanticsActions.OnClick) != null && n.config.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == "Google" } }
            assertNotNull(row.config[SemanticsActions.OnClick].action).invoke()
            val detail = draw("8-google-login")
            assertTrue(detail.any { it == "Google" } && detail.any { DemoVault.EMAIL in it }, "the Google login is open: $detail")
            assertTrue(detail.none { it == "Amazon" }, "the detail stands in place of the list: $detail")
        } finally {
            scene.close()
        }
    }

    private companion object {
        const val WIDTH = 1600
        const val HEIGHT = 1000
    }

    private fun textOf(n: SemanticsNode): String? =
        (n.config.getOrNull(SemanticsProperties.Text).orEmpty() + listOfNotNull(n.config.getOrNull(SemanticsProperties.EditableText)))
            .joinToString(" ") { it.text }.takeIf { it.isNotBlank() }

    private fun row(top: Int, text: String): String {
        val keys = placeholderKeys(text)
        val mark = if ("⟦" in text) "AWAITING ${keys.ifEmpty { listOf("(no key found)") }.joinToString(" ")}" else "final"
        return "$top\t$mark\t${text.replace('\n', ' ')}\n"
    }

    /**
     * The keys a placeholder's text stands for: the desktop's own [Placeholder] whose gloss it shows, a reserved [CopyKey]
     * whose name it carries, or a [CopyKey] awaiting its words whose fixed parts it holds. For the report only.
     */
    private fun placeholderKeys(text: String): List<String> {
        if ("⟦" !in text) return emptyList()
        val out = ArrayList<String>()
        for (p in Placeholder.entries) {
            if (p.words != null || p == Placeholder.RESERVED_COPY) continue
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
}

/**
 * The demo vault, given to the fake app interface through what it offers: an account on its public server, two contacts,
 * a shared vault with its members, and the items seeded as the vault content stores them (so a login's "last checked"
 * and its one-time code are set as a saved item holds them). The phone's pictures build the same vault.
 */
private object DemoVault {
    const val EMAIL = "jordan@example.com"
    const val HOME = "Home"
    private const val PASSWORD = "a made-up master password for the demo"
    private const val DAY = 86_400_000L

    /** The password Amazon and Spotify share: password health shows them as one reused pair. */
    private const val SHARED = "Demo-Shared-Pinecone-Harbor-24"

    fun build(api: FakeAppApi) {
        val me = api.script.publicInstance.addAccount(EMAIL, PASSWORD)
        me.nameHere = "Jordan"
        val alex = me.addContact("Alex", compared = true)
        val sam = me.addContact("Sam", compared = true)
        val home = me.addVault(HOME, RoleInVault.OWNER)
        home.addMember("Alex", RoleInVault.WRITER, alex)
        home.addMember("Sam", RoleInVault.READER, sam)
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
        fun id(name: String) = c.state.items.first { it.name == name }.itemId
        c.setUpdatedAt(id("Everyday Visa"), now - 60 * DAY)
        c.setUpdatedAt(id("Home Wi-Fi"), now - 400 * DAY)
        c.setUpdatedAt(id("Alarm code"), now - 120 * DAY)
        // Synced once in the background, as the app does after the vault opens: no "not synced yet" line above the list.
        ok(runBlocking { c.syncQuietly() })
    }
}
