package io.silencelen.andvari.app.trust.screens

import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.runtime.CompositionLocalProvider
import androidx.core.app.ActivityOptionsCompat
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import app.cash.paparazzi.Snapshot
import app.cash.paparazzi.SnapshotHandler
import com.android.resources.Density
import com.android.resources.NightMode
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.trust.BuildConstants
import io.silencelen.andvari.app.trust.FirstVaultView
import io.silencelen.andvari.app.trust.LocalFirstPage
import io.silencelen.andvari.app.trust.LocalFirstSharingVault
import io.silencelen.andvari.app.trust.LocalFirstVaultView
import io.silencelen.andvari.app.trust.ListControls
import io.silencelen.andvari.app.trust.SignedInPage
import io.silencelen.andvari.app.trust.TrustApp
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.app.trust.LocalDrawnAsk
import io.silencelen.andvari.app.trust.SignOutAsk
import io.silencelen.andvari.app.trust.comparisonWords
import io.silencelen.andvari.app.trust.unlockWords
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.lang.reflect.Proxy
import app.cash.paparazzi.detectEnvironment

/** The API level whose platform data the renderer draws with; see [ScreenDrawing.paparazzi]. */
internal const val DRAWN_AT_API = 35

/**
 * Every screen of the app drawn to an image, from the fake app interface's scenes (the same stand-in data the other
 * unit tests use), so they can be looked at with no phone. Paparazzi, tests only (owner-approved 2026-11-16).
 *
 * Run on request only (the build leaves this class out otherwise):
 * `gradle-locked.sh --offline :app-android:testDebugUnitTest -PandvariScreens --tests '*ScreenImagesTest'`.
 * The images land in `app-android/build/android-screens/<variant>/<shot>.png`, with `shots.tsv` listing every shot's
 * group, name and caption, and `failed.tsv` any shot that could not be drawn. Nothing here compares images: they are
 * for looking at.
 *
 * Each of the eight tests draws every shot in one variant: a small phone (Nexus 5, 360 × 640 dp) or a large one
 * (Pixel 6 Pro, 412 × 892 dp), light or dark, at the normal font scale or the largest the system offers (2.0).
 */
class ScreenImagesTest : ScreenDrawing(fullResolution = false) {
    @Test fun smallLightNormal() = drawAll("small-light-normal")

    @Test fun smallDarkNormal() = drawAll("small-dark-normal")

    @Test fun smallLightLargest() = drawAll("small-light-largest")

    @Test fun smallDarkLargest() = drawAll("small-dark-largest")

    @Test fun largeLightNormal() = drawAll("large-light-normal")

    @Test fun largeDarkNormal() = drawAll("large-dark-normal")

    @Test fun largeLightLargest() = drawAll("large-light-largest")

    @Test fun largeDarkLargest() = drawAll("large-dark-largest")
}

/**
 * Every shot once more as the whole page: the small phone's width, light, normal font, on a screen 2800 dp tall, so a
 * long page (Settings, Sharing) shows what lies below the first screenful. Kept at full resolution (2 pixels a dp).
 */
class ScreenImagesWholePageTest : ScreenDrawing(fullResolution = true) {
    @Test fun wholePage() = drawAll("whole-light")
}

/** What both drawing classes share: the image writer, the Paparazzi rule and the loop over every shot. */
abstract class ScreenDrawing(fullResolution: Boolean) {
    private val outDir: File = File(System.getProperty("andvari.screens.dir") ?: "build/android-screens")

    private var variant: Variant = Variant.all.first()

    /**
     * Writes each frame as `<variant>/<shot>.png` (Paparazzi has already scaled it to 1000 pixels high). The frame is a
     * `java.awt.image.BufferedImage`, which the unit tests' compile classpath (Android's) does not have, so the handler is
     * a proxy and the PNG is written through reflection; the test JVM itself has AWT.
     */
    private val writer: SnapshotHandler = run {
        val loader = SnapshotHandler::class.java.classLoader
        fun objectMethod(proxy: Any, name: String, args: Array<out Any?>?): Any? = when (name) {
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.get(0)
            "toString" -> "ScreenImagesTest.writer"
            else -> null
        }
        Proxy.newProxyInstance(loader, arrayOf(SnapshotHandler::class.java)) { proxy, method, args ->
            if (method.name != "newFrameHandler") return@newProxyInstance objectMethod(proxy, method.name, args)
            val snapshot = args[0] as Snapshot
            Proxy.newProxyInstance(loader, arrayOf(SnapshotHandler.FrameHandler::class.java)) { frame, m, a ->
                if (m.name != "handle") return@newProxyInstance objectMethod(frame, m.name, a)
                val f = File(outDir, "${variant.id}/${snapshot.name}.png")
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
        // The app targets API 36 and compiles against 35 (the module's build script says why). The renderer
        // (layoutlib 14.0.11 under Paparazzi 1.3.5) would take the platform data it draws with from the target, so it
        // is told the compile level instead: the drawings use the API 35 platform, matching the android.jar the
        // unit tests run against.
        environment = detectEnvironment().copy(compileSdkVersion = DRAWN_AT_API),
        deviceConfig = Variant.all.first().config,
        snapshotHandler = writer,
        supportsRtl = true,
        useDeviceResolution = fullResolution,
    )

    /** One way the screens are drawn. */
    class Variant(val id: String, val config: DeviceConfig, val widthDp: Int) {
        companion object {
            private val SMALL = DeviceConfig.NEXUS_5
            private val LARGE = DeviceConfig.PIXEL_6_PRO

            private fun v(size: String, base: DeviceConfig, widthDp: Int, dark: Boolean, font: Float) = Variant(
                "$size-${if (dark) "dark" else "light"}-${if (font > 1f) "largest" else "normal"}",
                base.copy(nightMode = if (dark) NightMode.NIGHT else NightMode.NOTNIGHT, fontScale = font),
                widthDp,
            )

            val all: List<Variant> = buildList {
                for ((size, base, width) in listOf(Triple("small", SMALL, 360), Triple("large", LARGE, 412))) {
                    for (font in listOf(1f, 2f)) for (dark in listOf(false, true)) add(v(size, base, width, dark, font))
                }
                add(
                    Variant(
                        "whole-light",
                        SMALL.copy(
                            screenWidth = 720, screenHeight = 5600, xdpi = 320, ydpi = 320, density = Density.XHIGH,
                            nightMode = NightMode.NOTNIGHT, fontScale = 1f,
                        ),
                        360,
                    ),
                )
            }
        }
    }

    protected fun drawAll(variantId: String) {
        val variant = Variant.all.first { it.id == variantId }
        this.variant = variant
        paparazzi.unsafeUpdateConfig(deviceConfig = variant.config)
        outDir.mkdirs()
        val failed = mutableListOf<String>()
        // -PandvariScreensOnly: only the shots named there; a full redraw otherwise.
        val only = System.getProperty("andvari.screens.only")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
        for (shot in Shots.all) {
            if (only != null && shot.name !in only) continue
            try {
                val (m, page, view, sharingVault, ask, window) = shot.make()
                paparazzi.snapshot(name = shot.name) {
                    CompositionLocalProvider(
                        LocalDrawnAsk provides ask,
                        LocalFirstPage provides page,
                        LocalFirstSharingVault provides sharingVault,
                        LocalFirstVaultView provides view,
                        LocalActivityResultRegistryOwner provides NoResults,
                    ) {
                        AndvariTheme {
                            if (window != null) {
                                androidx.compose.material3.Surface(color = androidx.compose.material3.MaterialTheme.colorScheme.background) { window() }
                            } else {
                                TrustApp(m)
                            }
                        }
                    }
                }
            } catch (t: Throwable) {
                failed += "${variant.id}\t${shot.name}\t${t.javaClass.name}: ${t.message?.lineSequence()?.firstOrNull()}"
            }
        }
        File(outDir, "shots.tsv").writeText(Shots.all.joinToString("") { "${it.group}\t${it.name}\t${it.caption}\n" })
        File(outDir, "failed-${variant.id}.tsv").writeText(failed.joinToString("") { "$it\n" })
    }
}

/** The file pickers and the scanner's permission ask register for a result; in a drawing nothing is ever launched. */
private object NoResults : ActivityResultRegistryOwner {
    override val activityResultRegistry: ActivityResultRegistry = object : ActivityResultRegistry() {
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {}
    }
}

/** What a shot draws: the model, and for an open account the page, the vault view and the shared vault's page it opens on. */
internal data class Drawn(
    val model: TrustModel,
    val page: SignedInPage? = null,
    val view: FirstVaultView? = null,
    val sharingVault: String? = null,
    /** A sign-out or switch confirmation already open at the step drawn ([LocalDrawnAsk]). */
    val ask: SignOutAsk? = null,
    /** A window of its own (the autofill windows), drawn in place of the app. */
    val window: (@androidx.compose.runtime.Composable () -> Unit)? = null,
)

/** One screen in one state: its group (as the app groups its screens), its file name, and a one-line caption. */
internal class Shot(val group: String, val name: String, val caption: String, val make: () -> Drawn)

/** Every shot, in the order a person meets the screens. */
internal object Shots {
    private fun api(scene: FakeScene): FakeAppApi = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)

    private fun model(api: FakeAppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also { it.onSnapshot(api.snapshot) }

    private fun at(scene: FakeScene, page: SignedInPage? = null, prep: (FakeAppApi, TrustModel) -> Unit = { _, _ -> }): () -> Drawn = {
        val api = api(scene)
        val m = model(api)
        prep(api, m)
        m.onSnapshot(api.snapshot)
        Drawn(m, page)
    }

    /** Sharing opened on one shared vault's own page, the vault [pick] names in [scene]'s account. */
    private fun vaultPage(scene: FakeScene, pick: (io.silencelen.andvari.core.app.AccountSnapshot) -> String): () -> Drawn = {
        val api = api(scene)
        val m = model(api)
        Drawn(m, SignedInPage.SHARING, null, pick(requireNotNull(api.snapshot.account)))
    }

    /** "Dana", a contact already, answers a connect link of this account under a new key: the creator's prompt. */
    private fun contactAnswersUnderANewKey(api: FakeAppApi): io.silencelen.andvari.core.app.AccountPrompt.KeyChanged {
        val dana = requireNotNull(api.script.unnamedDeviceAddsContact("Dana"))
        runBlocking { api.links.createConnectLink(emptyList(), 60) }
        check(api.script.contactAnswersUnderNewKey(requireNotNull(api.snapshot.account?.links).links.single(), dana))
        return requireNotNull(api.snapshot.account).prompts.filterIsInstance<io.silencelen.andvari.core.app.AccountPrompt.KeyChanged>().single()
    }

    /** Family's owner (this account) offers its ownership to another member who can take it; the members list closes. */
    private fun offerToAnotherMember(api: FakeAppApi, m: TrustModel) {
        val family = requireNotNull(api.snapshot.account).vaults.first { it.name == "Family" }
        m.run({ vaults.openMembers(family) })
        val to = requireNotNull(api.snapshot.account?.members).members.first { it.role != RoleInVault.OWNER && it.who is io.silencelen.andvari.core.app.PersonName.Contact }
        m.run({ vaults.offerOwnership(to) })
        m.act { vaults.closeMembers() }
    }

    /**
     * The fake's log as if a third member made the offer: this account becomes a writer, and the member who is neither
     * this account nor the person offered becomes the owner.
     */
    internal fun handOwnershipToSomeoneElse(api: FakeAppApi, vault: io.silencelen.andvari.core.app.fake.FakeVault) {
        val me = requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        val offered = requireNotNull(vault.offer).toUserId
        vault.role = RoleInVault.WRITER
        vault.members.filter { it.role == RoleInVault.OWNER }.forEach { it.role = RoleInVault.WRITER }
        vault.members.first { it.userId != me.userId && it.userId != offered }.role = RoleInVault.OWNER
        api.script.changed()
    }

    /** A login saved while the server does not answer: one more change waits on this phone. */
    private fun FakeAppApi.offlineSave(name: String) {
        val c = requireNotNull(fakeContent)
        c.setOffline(true)
        check(runBlocking { c.saveLogin(null, LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false), null) } == ActionResult.Ok)
    }

    /** [scene] after [prep], with the confirmation [ask] makes open at the step it walks to (sign-out or switch). */
    private fun asking(scene: FakeScene, page: SignedInPage?, prep: (FakeAppApi) -> Unit, ask: (FakeAppApi, TrustModel) -> SignOutAsk): () -> Drawn = {
        val api = api(scene)
        val m = model(api)
        prep(api)
        m.onSnapshot(api.snapshot)
        val a = ask(api, m)
        m.onSnapshot(api.snapshot)
        Drawn(m, page, ask = a)
    }

    private fun content(m: TrustModel): VaultContent =requireNotNull(m.content.value) { "the vault is not open" }

    private fun personal(c: VaultContent): String = c.vaultsForNewItems().first { it.personal }.vaultId

    /** A vault with a few items of each kind, one with a long name, one with a right-to-left name. */
    private fun fill(c: VaultContent) {
        val v = personal(c)
        val pw = c.generatePassword(GeneratorSettings.standard)
        fun ok(r: ActionResult) = check(r == ActionResult.Ok) { "the fake refused a save: $r" }
        runBlocking {
            ok(c.saveLogin(null, LoginInput("GitHub", "ada@example.com", pw, listOf("https://github.com"), "", "", true), v))
            ok(c.saveLogin(null, LoginInput("Bank of the North", "ada.lovelace", pw, listOf("https://bank.example"), "Branch 12", "JBSWY3DPEHPK3PXP", false), v))
            ok(c.saveLogin(null, LoginInput("The very long name of a login for a municipal water and electricity customer portal", "a.very.long.username.for.this.site@subdomain.example.com", pw, listOf("https://portal.utilities.city.example/customer/login"), "", "", false), v))
            ok(c.saveLogin(null, LoginInput("بنك القاهرة", "ada", pw, listOf("https://bank.example.eg"), "", "", false), v))
            ok(c.saveCard(null, CardInput("Everyday card", "Ada Lovelace", "4111111111111111", "07", "31", "123", "94110", "", false), v))
            ok(c.saveNote(null, NoteInput("Wi-Fi at home", "Network: hoard\nPassword: correct horse battery staple", false), v))
        }
    }

    private fun filled(): (FakeAppApi, TrustModel) -> Unit = { _, m -> fill(content(m)) }

    private fun itemNamed(m: TrustModel, name: String): String = content(m).state.items.first { it.name == name }.itemId

    /** A vault view: the vault filled, then [view] opened on it. */
    private fun vaultView(view: (TrustModel) -> FirstVaultView?, more: (VaultContent) -> Unit = {}, page: SignedInPage = SignedInPage.VAULT): () -> Drawn = {
        val api = api(FakeScene.VAULTS)
        val m = model(api)
        fill(content(m))
        more(content(m))
        Drawn(m, page, view(m))
    }

    private val FAMILY = "00000000-0000-4000-8000-0000000fa111"

    /** The filled vault beside a shared vault this account only reads, with two items in it. */
    private fun withShared(api: FakeAppApi, c: VaultContent) {
        val fake = requireNotNull(api.fakeContent)
        fake.addSharedVault(FAMILY, "Family", io.silencelen.andvari.core.client.items.VaultAccess.ROLE_READER, io.silencelen.andvari.core.client.items.VaultStanding.VERIFIED)
        fake.seedLogin(FAMILY, "Family router", "admin", "router-pw", "https://router.example")
        fake.seedCard(FAMILY, "Groceries card", "5555555555554444", "03", "2030")
        // A spread of last changes, so "recently updated" differs from the name order.
        c.state.items.forEachIndexed { i, it -> fake.setUpdatedAt(it.itemId, 1_800_000_000_000L - i * 3_600_000L * (if (i % 2 == 0) 1 else 7)) }
    }

    private fun sharedList(controls: ListControls?): () -> Drawn = sharedView({ FirstVaultView(controls = controls) })

    /** [vaultView] over the filled vault with the shared one beside it. */
    private fun sharedView(view: (TrustModel) -> FirstVaultView?, more: (FakeAppApi, VaultContent) -> Unit = { _, _ -> }): () -> Drawn = {
        val api = api(FakeScene.VAULTS)
        val m = model(api)
        fill(content(m))
        withShared(api, content(m))
        more(api, content(m))
        Drawn(m, SignedInPage.VAULT, view(m))
    }

    val all: List<Shot> = buildList {
        fun s(group: String, name: String, caption: String, make: () -> Drawn) = add(Shot(group, name, caption, make))
        fun e(group: String, scene: FakeScene, caption: String) = s(group, scene.name.lowercase().replace('_', '-'), caption, at(scene))

        val first = "1 First screen and choosing a server"
        e(first, FakeScene.FIRST_RUN, "The first screen: scan an invite, create an account on the public server, or use your own; sign in below.")
        e(first, FakeScene.FIRST_RUN_SIGNUP_FULL, "The first screen while the public server takes no new accounts.")
        e(first, FakeScene.FIRST_RUN_SIGNUP_NOT_KNOWN, "The first screen before the public server has answered.")
        e(first, FakeScene.FIRST_RUN_NO_PUBLIC_INSTANCE, "The first screen of a build with no public server baked in.")
        e(first, FakeScene.FIRST_RUN_HELP_WAITING, "The first screen with an operator's help waiting for this device.")
        e(first, FakeScene.FIRST_RUN_RECOVERY_STOPPED, "The first screen after a recovery was stopped at the account check.")
        s(first, "first-run-held-operator", "A hand-over made this phone's account its server's operator: the phone stopped using it, keeps it locked, and offers to remove it.", at(FakeScene.VAULTS) { api, _ ->
            api.script.handoverMadeThisAccountTheOperator()
        })
        s(first, "first-run-deletion-unknown-no-copy", "The first screen after a deletion nobody can tell, once this phone's copy of that account was signed out: the line no longer says the copy is kept.", at(FakeScene.DELETION) { api, m ->
            api.script.deletionAnswerLost = true
            api.script.deletionHappenedAnyway = true
            val deletion = requireNotNull(api.snapshot.account?.deletion)
            m.runIn(io.silencelen.andvari.app.trust.DELETION_SECTION, { this.settings.deleteAccount(deletion, deletion.email, FakeScenes.PASSWORD, null) }) { m.deletionAnswered(it) }
            m.onSnapshot(api.snapshot)
            m.runIn(io.silencelen.andvari.app.trust.DELETION_SECTION, { this.settings.checkDeletion(requireNotNull(snapshot.account?.deletion)) })
            m.onSnapshot(api.snapshot)
            api.signInAgain(requireNotNull(api.snapshot.locked))
            m.onSnapshot(api.snapshot)
            val ask = m.signOutAsk()
            ask.open()
            ask.confirm()
            ask.confirm()
        })
        e(first, FakeScene.OLD_DATA_LEFT,"The notice that an old store could not be removed at the first launch.")
        e(first, FakeScene.INVITE_ENTRY, "Scan or paste an invite.")
        e(first, FakeScene.OWN_SERVER, "Use your own server: type its address.")
        e(first, FakeScene.GATE_TYPED_ADDRESS, "The Trust Gate for a typed address.")
        e(first, FakeScene.GATE_ENROL_LINK, "The Trust Gate for an invite link.")
        e(first, FakeScene.GATE_DEVICE_LINK, "The Trust Gate for a device link.")
        e(first, FakeScene.GATE_SIGN_IN_AFTER_INVITE, "The Trust Gate when signing in after an invite.")
        e(first, FakeScene.GATE_KIT_IDENTITY_CHANGED, "The Trust Gate for a recovery kit whose server's identity changed.")
        e(first, FakeScene.GATE_TYPED_KIT, "The Trust Gate for a recovery kit typed by hand.")
        e(first, FakeScene.ADDRESS_MISMATCH, "A typed address whose server serves a card made for another address.")
        e(first, FakeScene.ADDRESS_MISMATCH_KIT, "A kit from before its server moved: offers to recover at the card's address.")
        e(first, FakeScene.SERVER, "A chosen server: what it offers.")
        e(first, FakeScene.SERVER_INVITATION_ONLY, "A chosen server that takes accounts by invitation only.")
        e(first, FakeScene.JOIN_INVITE, "Join with an invite.")
        e(first, FakeScene.NOT_TAKING_ACCOUNTS, "A server that takes no new accounts.")

        val signUp = "2 Creating an account and the recovery kit"
        e(signUp, FakeScene.SIGN_UP_EMAIL, "Sign-up on the public server: the email address and the age check.")
        e(signUp, FakeScene.SIGN_UP_PROVING_WORK, "Sign-up: the proof of work running.")
        e(signUp, FakeScene.SIGN_UP_CODE, "Sign-up: the code from the email.")
        e(signUp, FakeScene.CREATE_ACCOUNT, "Create the account: name and master password.")
        e(signUp, FakeScene.CREATE_ACCOUNT_INVITED, "Create the account from an invite.")
        e(signUp, FakeScene.CREATE_ACCOUNT_ENROLLED, "Create the account from an enrol link.")
        e(signUp, FakeScene.CREATE_ACCOUNT_RECOVERY_CHOICE, "Create the account: who can recover it.")
        e(signUp, FakeScene.RECOVERY_WARNING, "The warning when nobody else can recover the account.")
        e(signUp, FakeScene.KIT_REVEAL, "The recovery kit: its groups and QR code, print or save, no Copy.")
        e(signUp, FakeScene.KIT_CONFIRM, "The recovery kit: type three groups back.")
        e(signUp, FakeScene.KIT_MAKING, "The recovery kit being made.")
        e(signUp, FakeScene.KIT_NOT_MADE, "The recovery kit could not be made.")
        s(signUp, "kit-registered-not-kept", "An account the server made while this phone refused its session (another account kept meanwhile): its first kit, with its line and how long the kit holds.", at(FakeScene.CREATE_ACCOUNT) { api, m ->
            api.script.anotherAccountTakenDuringCommit = true
            val form = requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.CreateAccount)
            m.run({ entry.createAccount(form, io.silencelen.andvari.core.app.NewAccountInput(form.fixedEmail ?: "new@example.com", "Ada", "a much longer master password, 2026!", true)) })
        })
        s(signUp, "create-account-escrow-wrong-form", "The server no longer takes the kind of recovery copy this app makes: no account was made.", at(FakeScene.CREATE_ACCOUNT) { api, m ->
            api.script.escrowWrongForm = true
            val form = requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.CreateAccount)
            m.run({ entry.createAccount(form, io.silencelen.andvari.core.app.NewAccountInput(form.fixedEmail ?: "new@example.com", "Ada", "a much longer master password, 2026!", true)) })
        })

        val signIn = "3 Signing in and linking this phone"
        e(signIn, FakeScene.SIGN_IN_CHOICE, "Sign in: which server.")
        e(signIn, FakeScene.SIGN_IN_SERVER, "Sign in: type your server's address.")
        e(signIn, FakeScene.SIGN_IN, "Sign in: email and master password, naming the server.")
        e(signIn, FakeScene.SIGN_IN_CODE_NEEDED, "Sign in: the one-time code asked on the same screen.")
        /** A sign-in refused because this phone remembers an earlier account under the address, a copy of it kept here. */
        fun earlierRefused(api: FakeAppApi, m: TrustModel) {
            api.script.publicInstance.addAccount(FakeScenes.EMAIL, FakeScenes.PASSWORD)
            api.script.earlierAccountKnown = true
            api.script.earlierCopyKept = true
            api.script.identityFault = true
            m.run({ entry.submitSignIn(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        }
        s(signIn, "earlier-account-offer", "This phone knows the address under an earlier account: the refusal says both possibilities (the account was deleted and made again; or the server is not giving this phone the account it knows) and how to tell, and offers to forget the earlier account here. Neither button is preferred.",
            at(FakeScene.SIGN_IN) { api, m -> earlierRefused(api, m) })
        s(signIn, "earlier-account-confirm", "Its second step: what goes, the copy of the earlier account kept here (what cannot be told of its changes), that it cannot be undone, and what it means if the account was not made again.",
            at(FakeScene.SIGN_IN) { api, m ->
                earlierRefused(api, m)
                m.askToForgetEarlierAccount()
            })
        s(signIn, "earlier-account-forget-failed", "The forgetting failed part-way: said in place, the second step stays for the next tap; andvari never tries it again by itself.",
            at(FakeScene.SIGN_IN) { api, m ->
                earlierRefused(api, m)
                api.script.forgetFailsOnce = true
                m.askToForgetEarlierAccount()
                m.forgetEarlierAccount()
            })
        s(signIn, "earlier-account-forgotten", "Forgotten: the sign-in screen stays, for the person to sign in again.",
            at(FakeScene.SIGN_IN) { api, m ->
                earlierRefused(api, m)
                m.askToForgetEarlierAccount()
                m.forgetEarlierAccount()
            })
        s(signIn, "earlier-account-remembered", "The next sign-in under the address: above the vault, once, that this phone now remembers the new account, until dismissed.",
            at(FakeScene.SIGN_IN, SignedInPage.VAULT) { api, m ->
                earlierRefused(api, m)
                m.askToForgetEarlierAccount()
                m.forgetEarlierAccount()
                m.run({ entry.submitSignIn(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
            })
        s(signIn, "earlier-account-confirm-no-copy", "The second step where no copy of the earlier account is kept here: what goes, and that it cannot be undone. It says nothing of changes not sent, also where that account's signed changes to a shared vault were never sent (the forgetting removes them).",
            at(FakeScene.SIGN_IN) { api, m ->
                api.script.publicInstance.addAccount(FakeScenes.EMAIL, FakeScenes.PASSWORD)
                api.script.earlierAccountKnown = true
                api.script.identityFault = true
                m.run({ entry.submitSignIn(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
                m.askToForgetEarlierAccount()
            })
        s(signIn, "earlier-account-not-confirmed", "The second step confirmed after the address came to name the account the server serves: nothing forgotten, said in its line; no offer stands.",
            at(FakeScene.SIGN_IN) { api, m ->
                earlierRefused(api, m)
                m.askToForgetEarlierAccount()
                api.script.addressTiedToServed = true
                m.forgetEarlierAccount()
            })
        s(signIn, "earlier-account-nothing-to-forget", "The second step confirmed after the earlier account was already forgotten here (another start of the app): nothing to forget, said in its line; no offer stands.",
            at(FakeScene.SIGN_IN) { api, m ->
                earlierRefused(api, m)
                api.script.forgetAnswer = io.silencelen.andvari.core.app.ForgetEarlierResult.NOTHING_TO_FORGET
                m.askToForgetEarlierAccount()
                m.forgetEarlierAccount()
            })
        s(signIn, "same-account-other-key", "The server serves the account this phone knows under the address with another key: the identity fault's own line, and nothing offered to forget.",
            at(FakeScene.SIGN_IN) { api, m ->
                api.script.publicInstance.addAccount(FakeScenes.EMAIL, FakeScenes.PASSWORD)
                api.script.earlierAccountKnown = true
                api.script.sameAccountOtherKey = true
                api.script.identityFault = true
                m.run({ entry.submitSignIn(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
            })
        /** The server signed this phone's account out; signing in to it again, on the same server. */
        fun signInOverKept(api: FakeAppApi) {
            api.script.sessionEndedByServer()
            api.signInAgain(requireNotNull(api.snapshot.locked))
            api.entry.openSignIn(requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.FirstRun))
            api.entry.openPasswordSignIn(requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignInChoice))
            runBlocking { api.entry.choosePublicInstance(requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignInServer)) }
        }
        s(signIn, "sign-in-server-keys-not-known", "Signing in to the account this phone keeps, where the server's keys are not the ones this phone knows: nothing was opened or changed; the way out, and signing out of this phone's copy.", at(FakeScene.VAULTS) { api, m ->
            signInOverKept(api)
            api.script.signInServerKeysNotKnown = true
            m.run({ entry.submitSignIn(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        })
        fun signInHere(m: TrustModel, email: String, password: String) =
            m.run({ entry.submitSignIn(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), email, password) })
        s(signIn, "sign-in-kept-copy-damaged", "Signing in to the account this phone keeps, whose copy here is damaged: its sentence, and the removal of this phone's copy (its count first, behind a confirmation).", at(FakeScene.VAULTS) { api, m ->
            signInOverKept(api)
            api.script.keeperRefuses = "kept_copy_damaged"
            signInHere(m, FakeScenes.EMAIL, FakeScenes.PASSWORD)
        })
        s(signIn, "sign-in-operator-held", "Signing in while this phone holds its server's operator account: its sentence, and Remove (on the first screen, behind its confirmation); never a sign-out.", at(FakeScene.SIGN_IN) { api, m ->
            api.script.publicInstance.addAccount("ada@example.com", "a brand new master password")
            api.script.keeperRefuses = "operator_account_held"
            signInHere(m, "ada@example.com", "a brand new master password")
        })
        s(signIn, "sign-in-refused-after-code", "A two-step code the server did not take: its own sentence, back at the master password (never the wrong-password line).", at(FakeScene.SIGN_IN_CODE_NEEDED) { api, m ->
            m.submitSignInCode(requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), "000000")
        })
        s(signIn, "sign-in-code-step-spent", "A two-step code answered with a stop that keeps the code step: the field gives way to Start the sign-in again (another code would only be refused).", at(FakeScene.SIGN_IN_CODE_NEEDED) { api, m ->
            api.script.keeperRefuses = "kept_copy_damaged"
            m.submitSignInCode(requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), "654321")
        })
        s(signIn, "signed-in-copy-follows-server", "Signed in over a copy that was sealed under another master password: the notice above the vault, once, with Close.", at(FakeScene.VAULTS) { api, m ->
            signInOverKept(api)
            api.script.signInOverOtherPasswordCopy = true
            m.run({ entry.submitSignIn(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.SignIn), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        })
        s(signIn, "link-device-ended-operator-held", "Linking this phone ended because it holds its server's operator account: the sentence and Remove (on the first screen, behind its confirmation).", at(FakeScene.LINK_DEVICE_CODE) { api, _ ->
            api.script.keeperRefuses = "operator_account_held"
            api.script.otherDeviceApproves()
        })
        e(signIn, FakeScene.SERVER_CHANGED, "A pinned server that moved, found when signing in.")
        e(signIn, FakeScene.SERVER_STOPPED, "A pinned server whose identity forked: the stop and Forget this server.")
        e(signIn, FakeScene.SERVER_WITHHELD, "A pinned server that serves an older card.")
        e(signIn, FakeScene.LINK_REQUIRED, "This phone must be linked from another device.")
        e(signIn, FakeScene.LINK_DEVICE_ENTRY, "Link from your other device: scan or paste its link.")
        e(signIn, FakeScene.LINK_DEVICE_WAITING, "Link: waiting for the other device.")
        e(signIn, FakeScene.LINK_DEVICE_CODE, "Link: the digits to type on the other device.")
        e(signIn, FakeScene.LINK_DEVICE_PASSWORD, "Link: the master password, after the other device approved.")
        e(signIn, FakeScene.LINK_DEVICE_CANCELLED, "Link: the other device cancelled.")
        s(signIn, "link-device-ended-too-many", "Link: the server refused the pickup as one of too many requests: its own line with the wait as a length of time, never \"unreachable\".", at(FakeScene.LINK_DEVICE_PASSWORD) { api, m ->
            api.script.linkTooMany = true
            runBlocking { m.run({ entry.submitLinkPassword(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.LinkDevicePassword), FakeScenes.PASSWORD) }).join() }
        })
        e(signIn, FakeScene.LINK_DEVICE_WRONG_SERVER, "Link: a link for another server.")

        val forgot = "4 Forgot the master password"
        e(forgot, FakeScene.FORGOT, "Forgot: the recovery kit, or the operator's help.")
        e(forgot, FakeScene.KIT_ENTRY, "Recover with the kit: scan or type it.")
        e(forgot, FakeScene.KIT_RECOVER, "Recover with the kit: the account it names.")
        s(forgot, "kit-same-account-other-key", "The kit of the account this phone knows, served under another key: the kit's check is refused with the identity fault's own line, nothing is changed, and nothing is offered to forget.",
            at(FakeScene.KIT_RECOVER) { api, m ->
                api.script.earlierAccountKnown = true
                api.script.sameAccountOtherKey = true
                api.script.identityFault = true
                m.run({ entry.confirmKitRecovery(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.KitRecover)) })
            })
        e(forgot, FakeScene.REPLACE_PASSWORD, "Recover: the new master password.")
        e(forgot, FakeScene.KIT_AFTER_RECOVERY, "Recover: the new kit after the recovery.")
        e(forgot, FakeScene.ASK_OPERATOR, "Ask the operator for help.")
        e(forgot, FakeScene.OPERATOR_HELP_CODE_NEEDED, "Operator help: the code needed.")
        e(forgot, FakeScene.OPERATOR_HELP_HOLDING, "Operator help: the waiting period running.")
        fun helping(m: TrustModel, api: FakeAppApi) = m.run({ entry.refreshOperatorHelp(snapshot.entry as io.silencelen.andvari.core.app.EntryScreen.OperatorHelp) })
        s(forgot, "operator-help-key-changed-unsigned", "Operator help: the operator's recovery key changed and the change is not signed: the warning, with Stop as the main button.", at(FakeScene.OPERATOR_HELP_HOLDING) { api, m ->
            api.script.advance(7 * 86_400_000L)
            api.script.operatorAnswers(forged = false)
            api.script.recoveryKeyChangesWhileRequestOpen(byOldKey = false)
            helping(m, api)
        })
        s(forgot, "operator-help-key-changed-signed", "Operator help: the key change signed later: the account check carries one dated line.", at(FakeScene.OPERATOR_HELP_HOLDING) { api, m ->
            api.script.advance(7 * 86_400_000L)
            api.script.operatorAnswers(forged = false)
            api.script.recoveryKeyChangesWhileRequestOpen(byOldKey = false)
            helping(m, api)
            api.script.recoveryKeyChangeSignedLater()
            helping(m, api)
        })
        s(forgot, "operator-help-request-unknown", "Operator help: a request the server no longer knows, with Wait and Start again.", at(FakeScene.OPERATOR_HELP_HOLDING) { api, _ ->
            api.script.serverForgetsRequest()
        })
        s(forgot, "first-run-late-recovery", "The first screen after a recovery the person left was answered late (here: refused), until dismissed.", at(FakeScene.OPERATOR_HELP_HOLDING) { api, m ->
            m.act { entry.startOver() }
            api.script.leftRecoveryAnswered(io.silencelen.andvari.core.app.LateRecoveryResult.REFUSED)
        })
        e(forgot, FakeScene.OPERATOR_HELP_AWAITING,"Operator help: waiting for the operator.")
        e(forgot, FakeScene.OPERATOR_HELP_VETOED, "Operator help: stopped from another device.")
        e(forgot, FakeScene.OPERATOR_HELP_NOT_GENUINE, "Operator help: the help could not be verified.")
        e(forgot, FakeScene.OPERATOR_HELP_CHECK_ACCOUNT, "Operator help: check this is your account.")
        e(forgot, FakeScene.REPLACE_PASSWORD_AFTER_HELP, "Operator help: the new master password.")
        fun choose(m: TrustModel, api: FakeAppApi) =
            m.run({ entry.chooseReplacementPassword(requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.ReplacePassword), "a brand new master password") })
        s(forgot, "kit-after-recovery-refused-here", "A recovery the server took while this phone refused the session (here: the identity fault): the result's sentence, how long the kit holds, then the new kit.", at(FakeScene.REPLACE_PASSWORD) { api, m ->
            api.script.refusedAfterCommit = "self_identity_mismatch"
            choose(m, api)
        })
        s(forgot, "kit-after-recovery-another-kept", "The same while another account was kept here meanwhile: the kit's line, the new password in force, how long the kit holds.", at(FakeScene.REPLACE_PASSWORD) { api, m ->
            api.script.anotherAccountTakenDuringCommit = true
            choose(m, api)
        })
        s(forgot, "kit-confirm-refused-here", "Its confirm step: the same lines stand above the three groups to type.", at(FakeScene.REPLACE_PASSWORD) { api, m ->
            api.script.refusedAfterCommit = "server_keys_not_known_here"
            choose(m, api)
            m.onSnapshot(api.snapshot)
            m.act { kit.proceedToConfirm(requireNotNull(snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.Kit).kit) }
        })
        s(forgot, "first-run-after-refused-kit", "That kit typed back: the first screen says the refusal again, with its way out where one is kept.", at(FakeScene.REPLACE_PASSWORD) { api, m ->
            api.script.anotherAccountTakenDuringCommit = true
            choose(m, api)
            m.onSnapshot(api.snapshot)
            val reveal = requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.Kit).kit
            val doc = requireNotNull(api.kit.kitDocument(reveal))
            m.act { kit.proceedToConfirm(reveal) }
            val confirm = requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.Kit).kit
            m.run({ kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        })
        s(forgot, "kit-idle-warning", "A kit shown with a refusal, twenty seconds before its idle limit: the shared code's warning above it, under the kit's line and how long it holds (a touch ends it; the lock takes the kit).", {
            var now = 0L
            val api = api(FakeScene.REPLACE_PASSWORD)
            val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { now }).also { it.onSnapshot(api.snapshot) }
            api.script.anotherAccountTakenDuringCommit = true
            choose(m, api)
            m.onSnapshot(api.snapshot)
            now = requireNotNull((api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.Kit)?.kit?.idleLockAfterMs) - 20_000
            m.tick()
            Drawn(m)
        })
        s(forgot, "kit-registered-identity-fault", "A registration the server took while this phone refused the session for a fault of the account's identity: its own sentence and how long the kit holds, then the first kit.", at(FakeScene.CREATE_ACCOUNT) { api, m ->
            api.script.refusedAfterCommit = "self_identity_mismatch"
            m.run({ entry.createAccount(requireNotNull(api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.CreateAccount), io.silencelen.andvari.core.app.NewAccountInput("", "Ada", "a brand new master password", true)) })
        })
        s(forgot, "first-run-committed-not-opened", "A recovery's commit went through but its answer did not open the account here (the engine's road, played by hand over the fake): said on the first screen.", {
            val inner = api(FakeScene.REPLACE_PASSWORD)
            val engine = io.silencelen.andvari.app.trust.EngineLike(inner)
            engine.entryOverride = object : io.silencelen.andvari.core.app.EntryApi by inner.entry {
                override suspend fun chooseReplacementPassword(screen: io.silencelen.andvari.core.app.EntryScreen.ReplacePassword, password: String): io.silencelen.andvari.core.app.ReplacePasswordResult {
                    inner.entry.startOver()
                    return io.silencelen.andvari.core.app.ReplacePasswordResult.COMMITTED_NOT_OPENED
                }
            }
            val m = TrustModel(engine, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also { it.onSnapshot(engine.snapshot) }
            m.run({ entry.chooseReplacementPassword(requireNotNull(engine.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.ReplacePassword), "a brand new master password") })
            m.onSnapshot(engine.snapshot)
            Drawn(m)
        })
        // The notice that a kit shown with a refusal was wiped by a lock: the fake's own (its lock plays the engine's),
        // walked to on another fake and laid over this scene's snapshot ([EngineLike]).
        fun wiped(scene: FakeScene, notice: io.silencelen.andvari.core.app.KitWipedNotice, prep: (FakeAppApi, TrustModel) -> Unit = { _, _ -> }): () -> Drawn = {
            val inner = api(scene)
            val engine = io.silencelen.andvari.app.trust.EngineLike(inner)
            val m = TrustModel(engine, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also { it.onSnapshot(engine.snapshot) }
            prep(inner, m)
            engine.kitWiped = notice
            m.onSnapshot(engine.snapshot)
            Drawn(m, SignedInPage.VAULT)
        }
        val notices = io.silencelen.andvari.app.trust.FakeKitNotices
        s(forgot, "kit-wiped-lock-screen", "The kit shown after a recovery another account's session stood in the way of was wiped by a lock: above the lock screen, the notice and what stands in the way here, until dismissed.",
            wiped(FakeScene.LOCKED, notices.afterRecoveryWhileKept()))
        s(forgot, "kit-wiped-first-screen", "A registration's first kit was wiped (a lock, or the app was closed with it on show): the notice above the first screen.",
            wiped(FakeScene.FIRST_RUN, notices.afterRegistration()))
        s(forgot, "kit-wiped-open-vault", "The notice stays through an opening: above the open vault, until the person dismisses it.",
            wiped(FakeScene.LOCKED, notices.afterRecovery()) { _, m ->
                m.run({ unlock(requireNotNull(snapshot.locked), FakeScenes.PASSWORD) })
            })
        s(forgot, "kit-wiped-first-screen-way-out", "The notice names an account kept here as what stands in the way: the first screen offers that account's sign-out (its count and both confirmations), with no sign-in tried first. The notice keeps only its Close.",
            wiped(FakeScene.VAULTS, notices.afterRecoveryWhileKept()) { api, _ ->
                api.script.sessionEndedByServer()
                api.signInAgain(requireNotNull(api.snapshot.locked))
            })
        s(forgot, "first-run-own-sign-out-overtook", "A master password change was still under way when the person signed out here: the first screen says it was not done because of their own sign-out, not that the server ended the session.", at(FakeScene.VAULTS) { api, m ->
            api.script.holdNext()
            m.runIn(io.silencelen.andvari.app.trust.PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { io.silencelen.andvari.app.trust.passwordChangeWords(it, 0) })
            val ask = m.signOutAsk()
            ask.open()
            ask.confirm()
            if (ask.step == io.silencelen.andvari.app.trust.SignOutAsk.Step.SECOND) ask.confirm()
            api.script.releaseHold()
        })
        s(forgot, "kit-entry-stopped-before-commit", "A recovery stopped just before its commit because another account is kept here now: said where the kit is handed in, with the sign-out.", at(FakeScene.REPLACE_PASSWORD) { api, m ->
            api.script.anotherAccountTakenBeforeCommit = true
            choose(m, api)
        })
        s(forgot, "operator-help-another-kept", "Operator help stopped before the commit because another account is kept here: in place of the stage, the request kept, Try again.", at(FakeScene.REPLACE_PASSWORD_AFTER_HELP) { api, m ->
            api.script.anotherAccountTakenBeforeCommit = true
            choose(m, api)
        })
        for ((reason, name) in listOf("operator_account_held" to "held-operator", "kept_copy_damaged" to "damaged-copy")) {
            s(forgot, "operator-help-$name", "Operator help: the answer arrived, and this phone's own reason stops it (${name.replace('-', ' ')}): its sentence and its way out, the request kept.", at(FakeScene.OPERATOR_HELP_HOLDING) { api, m ->
                api.script.advance(7 * 86_400_000L)
                api.script.operatorAnswers(forged = false)
                api.script.keeperRefuses = reason
                helping(m, api)
            })
        }

        val locked = "5 Locked"
        e(locked, FakeScene.LOCKED, "The lock screen, naming the account and the server.")
        s(locked, "kit-replaces-earlier", "An account whose kit was never confirmed: a lock took the kit shown at the last unlock, so this unlock shows a new one, and says first, in red, that the kit shown before no longer works.", at(FakeScene.LOCKED) { api, m ->
            api.script.publicInstance.accounts.values.first().kitSaved = false
            m.run({ unlock(requireNotNull(snapshot.locked), FakeScenes.PASSWORD) })
            m.act { lock() }
            m.run({ unlock(requireNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        })
        s(locked, "locked-wrong-password", "The lock screen after a wrong master password.", at(FakeScene.LOCKED) { api, m ->
            m.runSaying({ unlock(requireNotNull(snapshot.locked), "not the password") }, { unlockWords(it, 0) })
        })
        e(locked, FakeScene.LOCKED_SERVER_STOPPED, "Locked, with the server stopped on this device: no password opens it.")
        s(locked, "locked-keys-at-server", "Under a server policy that forbids keeping data on this phone: the lock screen says the account's keys are kept at the server, so every unlock asks it; no quick unlock.", at(FakeScene.LOCKED) { api, _ ->
            api.script.publicInstance.offlineCacheAllowed = false
            api.script.changed()
        })
        s(locked, "locked-keys-at-server-no-answer", "The same, after an unlock the server did not answer: the shared code's own sentence for it (nothing opened or removed; only the server can check the password), never \"wrong password\".", at(FakeScene.LOCKED) { api, m ->
            api.script.publicInstance.offlineCacheAllowed = false
            api.script.changed()
            api.script.publicInstance.reachable = false
            m.runSaying({ unlock(requireNotNull(snapshot.locked), FakeScenes.PASSWORD) }, { unlockWords(it, 0) })
        })
        s(locked, "locked-keys-at-server-ended", "Under that policy, a session the server ended: the shared code's line for that end (no key and no copy here opens the account; nothing opens until you sign in again), with Sign in again.", at(FakeScene.LOCKED) { api, _ ->
            api.script.publicInstance.offlineCacheAllowed = false
            api.script.sessionEndedByServer()
        })
        s(locked, "locked-keys-at-server-ended-unlock", "The same, after an unlock: the shared code's sentence that nothing opened or was removed and nothing opens until you sign in again.", at(FakeScene.LOCKED) { api, m ->
            api.script.publicInstance.offlineCacheAllowed = false
            api.script.sessionEndedByServer()
            m.runSaying({ unlock(requireNotNull(snapshot.locked), FakeScenes.PASSWORD) }, { unlockWords(it, 0) })
        })
        s(locked, "locked-keys-at-server-refused", "Under that policy, an unlock the server answered by refusing the keys: its own sentence, never \"did not answer\".", at(FakeScene.LOCKED) { api, m ->
            api.script.publicInstance.offlineCacheAllowed = false
            api.script.changed()
            api.script.forceNext(io.silencelen.andvari.core.app.VaultUnlockResult.KEYS_AT_SERVER_REFUSED)
            m.runSaying({ unlock(requireNotNull(snapshot.locked), FakeScenes.PASSWORD) }, { unlockWords(it, 0) })
        })
        s(locked, "locked-session-not-confirmed", "A session this phone could not confirm with its server in time: said as that end, never \"signed out by the server\".", at(FakeScene.LOCKED) { api, _ ->
            api.script.sessionNotConfirmed()
        })

        val vault = "6 The vault"
        s(vault, "vault-empty", "The open vault with no items yet.", at(FakeScene.VAULTS, SignedInPage.VAULT))
        s(vault, "vault-list", "The vault with items: a favourite, a long name, a right-to-left name, a card and a note.", at(FakeScene.VAULTS, SignedInPage.VAULT, filled()))
        s(vault, "vault-search-none", "A search that finds nothing.", at(FakeScene.VAULTS, SignedInPage.VAULT) { _, m -> fill(content(m)); content(m).setQuery("zzz") })
        s(vault, "item-login", "A login opened: user name, password hidden, web address, one-time code.", vaultView({ FirstVaultView(open = itemNamed(it, "Bank of the North")) }))
        s(vault, "item-login-long", "A login with a long name, user name and address.", vaultView({ FirstVaultView(open = itemNamed(it, "The very long name of a login for a municipal water and electricity customer portal")) }))
        s(vault, "item-login-rtl", "A login with a right-to-left name.", vaultView({ FirstVaultView(open = itemNamed(it, "بنك القاهرة")) }))
        s(vault, "item-card", "A card opened.", vaultView({ FirstVaultView(open = itemNamed(it, "Everyday card")) }))
        s(vault, "item-note", "A note opened.", vaultView({ FirstVaultView(open = itemNamed(it, "Wi-Fi at home")) }))
        s(vault, "editor-new-login", "The editor for a new login.", vaultView({ FirstVaultView(editKind = "login") }))
        s(vault, "editor-edit-login", "The editor for an existing login.", vaultView({ FirstVaultView(editKind = "login", editItem = itemNamed(it, "GitHub")) }))
        s(vault, "item-login-no-password", "A login with no password: no strength line, but when it was last used, as every login has.", vaultView({ FirstVaultView(open = itemNamed(it, "Single sign-on")) }, { c ->
            runBlocking { c.saveLogin(null, LoginInput("Single sign-on", "ada", "", listOf("https://sso.example"), "", "", false), personal(c)) }
        }))
        s(vault, "list-filtered-closed-vault", "The list filtered to a shared vault closed for writing while its deletion waits: why, above its items.", sharedView({ FirstVaultView(controls = ListControls(vaultId = FAMILY)) }) { _, c ->
            c.markVaultClosedForWriting(FAMILY, io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING)
        })
        s(vault, "editor-new-card", "The editor for a new card.", vaultView({ FirstVaultView(editKind = "card") }))
        s(vault, "editor-new-note", "The editor for a new note.", vaultView({ FirstVaultView(editKind = "note") }))
        s(vault, "trash-empty", "The trash, empty.", vaultView({ null }, { c -> runBlocking { c.openTrash() } }))
        s(vault, "trash-items", "The trash with a deleted login.", vaultView({ null }, { c ->
            runBlocking { c.deleteItem(c.state.items.first { it.name == "GitHub" }.itemId); c.openTrash() }
        }))
        s(vault, "history", "A login's history after an edit, opened in place on its detail as the current app's version history.", vaultView({ FirstVaultView(open = itemNamed(it, "GitHub")) }, { c ->
            val id = c.state.items.first { it.name == "GitHub" }.itemId
            runBlocking {
                c.saveLogin(id, LoginInput("GitHub", "ada@example.com", "a-newer-password", listOf("https://github.com"), "", "", true), personal(c))
                c.openItemHistory(id)
            }
        }))
        s(vault, "history-none-earlier", "A login never edited: its history has no earlier versions and says so in a line of its own.", vaultView({ FirstVaultView(open = itemNamed(it, "GitHub")) }, { c ->
            runBlocking { c.openItemHistory(c.state.items.first { it.name == "GitHub" }.itemId) }
        }))
        s(vault, "import-sheet","Import, from the vault's top bar: the current app's sheet before the file picker, with the sources, the plain-text warning and the export steps.", vaultView({ FirstVaultView(importAsked = true) }))
        s(vault, "history-restore-confirm", "Restore on an earlier version: the question first, with the version's date; only its confirm restores.", vaultView({ FirstVaultView(open = itemNamed(it, "GitHub"), restoreAsked = true) }, { c ->
            val id = c.state.items.first { it.name == "GitHub" }.itemId
            runBlocking {
                c.saveLogin(id, LoginInput("GitHub", "ada@example.com", "a-newer-password", listOf("https://github.com"), "", "", true), personal(c))
                c.openItemHistory(id)
            }
        }))
        s(vault, "health", "Vault health: a page of its own, its summary as the current app's tiles, and its three tabs with Passwords on show.", vaultView({ null }, { c -> c.openHealth() }))
        s(vault, "health-duplicates", "Vault health's Duplicates tab.", vaultView({ FirstVaultView(healthTab = io.silencelen.andvari.app.trust.HealthTab.DUPLICATES) }, { c -> c.openHealth() }))
        s(vault, "health-staleness", "Vault health's Staleness tab: logins by when they were last checked.", vaultView({ FirstVaultView(healthTab = io.silencelen.andvari.app.trust.HealthTab.STALENESS) }, { c -> c.openHealth() }))
        s(vault, "item-card-expired", "A card whose expiry month is over: \"expired\" beside its expiry, with Copy of the short date.", vaultView({ FirstVaultView(open = itemNamed(it, "Old card")) }, { c ->
            runBlocking { c.saveCard(null, CardInput("Old card", "Ada Lovelace", "5555555555554444", "03", "21", "", "", "", false), personal(c)) }
        }))
        s(vault, "editor-edit-card", "The editor for an existing card: the number's label names the brand its digits show.", vaultView({ FirstVaultView(editKind = "card", editItem = itemNamed(it, "Everyday card")) }))
        s(vault, "import", "Import a CSV: the current app's dialog over the vault, with the plan, Import and Cancel.", vaultView({ null }, { c ->
            runBlocking { c.importCsv("name,url,username,password\nShop,https://shop.example,ada,pw1\nMail,https://mail.example,ada,pw2\n".encodeToByteArray()) }
        }))
        s(vault, "deleted-vaults", "Deleted shared vaults that can still be restored, at the foot of Sharing as in the current app.", vaultView({ null }, { c -> runBlocking { c.openDeletedVaults() } }, SignedInPage.SHARING))
        s(vault, "vault-backup", "Settings with the vault open: the backups, where the current app has them.", vaultView({ null }, page = SignedInPage.SETTINGS))
        s(vault, "export-backup", "The encrypted backup opened from Settings.", vaultView({ null }, { c -> runBlocking { c.openExport(io.silencelen.andvari.core.app.ExportKind.BACKUP) } }, SignedInPage.SETTINGS))
        s(vault, "editor-discard", "Cancel in the editor asks before typed work goes.", vaultView({ FirstVaultView(editKind = "login", editItem = itemNamed(it, "GitHub"), discard = true) }))
        s(vault, "went-wrong", "The line above the screen when something went wrong and no vault was named: the general line.", at(FakeScene.VAULTS, SignedInPage.VAULT) { _, m -> m.fault(null) })
        s(vault, "went-wrong-in-vault", "The line above the screen when something went wrong in one vault that is open: the vault's line.", at(FakeScene.VAULTS, SignedInPage.VAULT) { _, m -> m.fault(io.silencelen.andvari.core.app.content.FakeVaultContent.PERSONAL_VAULT_ID) })
        s(vault, "went-wrong-locked", "Something went wrong while locked: the general line on the lock screen (nothing is open).", at(FakeScene.LOCKED) { _, m -> m.act { throw IllegalStateException("drawn") } })
        s(vault, "vault-list-shared", "The list with a shared vault this account only reads: each of its rows carries the vault's name, and the vault filter appears.", sharedList(null))
        s(vault, "vault-list-sorted-filtered", "The list sorted by the last change and cut to logins, as the current app's row of three offers.", sharedList(ListControls(recent = true, type = "login")))
        s(vault, "item-view-only", "An item of a vault this account only reads: \"view only\", and no Edit.", sharedView({ m -> FirstVaultView(open = itemNamed(m, "Family router")) }))
        s(vault, "trash-not-read", "The trash with a row this device has not read yet (it still offers Restore) and a row of a vault this account only reads.", sharedView({ null }) { api, c ->
            val fake = requireNotNull(api.fakeContent)
            fake.seedDeleted(personal(c), "Old bank", "ana", 3, notReadYet = true)
            fake.seedDeleted(FAMILY, "Their old router", "", 2)
            runBlocking { c.openTrash() }
        })
        s(vault, "trash-not-done", "A restore the server answered as done and did not perform: the warning at the next opening of the trash.", sharedView({ null }) { api, c ->
            val fake = requireNotNull(api.fakeContent)
            val id = fake.seedDeleted(personal(c), "Old bank", "ana", 3)
            fake.trashActionsStoreNothing(true)
            runBlocking {
                c.openTrash()
                c.restoreFromTrash(id)
                c.dismissNotice()
                c.openTrash()
            }
        })
        s(vault, "policy-copy-being-removed", "The server's policy forbids a copy on devices: while this phone's copy is being removed, the vault says so where a stopped server's line would be, and Add stays.", at(FakeScene.VAULTS, SignedInPage.VAULT) { api, _ ->
            requireNotNull(api.fakeContent).removingForPolicy()
        })
        s(vault, "policy-copy-removed-notice", "After the copy went under that policy: the notice above the screen with the shared code's lines (two changes lost, one that may or may not have arrived), until dismissed.", at(FakeScene.VAULTS, SignedInPage.VAULT) { api, _ ->
            api.script.policyCopyRemoved(notSent = 2, unsure = 1, serverName = "Home")
        })
        s(vault, "settings-captures-kept-sealed", "Settings under a server policy that forbids keeping data on this phone: with the server's rules, the line that logins andvari catches are kept here, sealed, until answered.", at(FakeScene.VAULTS, SignedInPage.SETTINGS) { api, _ ->
            api.script.publicInstance.offlineCacheAllowed = false
            api.script.changed()
        })
        s(vault, "move-note-half-made-kept", "After \"Move everything\" kept a half-made vault of an earlier try: the note at the top of the page, with the member who still holds it, until Close.", at(FakeScene.VAULTS, SignedInPage.VAULT) { api, _ ->
            runBlocking {
                api.vaults.openMembers(requireNotNull(api.snapshot.account).vaults.first { it.name == "Family" })
                val member = requireNotNull(api.snapshot.account?.members).members.first { it.who is io.silencelen.andvari.core.app.PersonName.Contact }
                api.vaults.openMoveEverythingRemoving(member)
                api.script.nextMoveKeepsHalfMade = 1
                api.vaults.moveEverything(requireNotNull(api.snapshot.account?.moving), "Family 2")
            }
        })
        s(vault, "policy-copy-removed-notice-locked", "The same notice on the lock screen: a lock never takes it away.", at(FakeScene.VAULTS) { api, _ ->
            api.script.policyCopyRemoved(notSent = 3, cannotTell = true, unopened = false, serverName = "Home")
            api.lock()
        })

        val sharing = "7 Sharing: shared vaults, people and links"
        fun sh(scene: FakeScene, caption: String) = s(sharing, scene.name.lowercase().replace('_', '-'), caption, at(scene, SignedInPage.SHARING))
        sh(FakeScene.VAULTS, "The sharing page: shared vaults, people and links.")
        s(sharing, "vault-deleted-no-day", "A shared vault deleted on a server that served no day for its grace: its row says the line that names no day (Restore is on the vault's own page; Delete, Rename and Move everything are not offered there).", at(FakeScene.VAULTS, SignedInPage.SHARING) { api, _ ->
            api.script.servesGraceDay = false
            runBlocking { api.vaults.deleteVault(requireNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) }
        })
        s(sharing, "vaults-long-and-rtl-names", "Shared vaults with a long name and a right-to-left name.", at(FakeScene.VAULTS, SignedInPage.SHARING) { api, _ ->
            val me = requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
            me.addVault("The extended family's shared logins for the holiday house and the boat", RoleInVault.OWNER)
            me.addVault("خزنة العائلة", RoleInVault.WRITER)
            api.script.changed()
        })
        sh(FakeScene.VAULT_STATES, "Every state a shared vault's row can be in: frozen, failed, withheld, removed, and so on.")
        s(sharing, "vault-stranger-shares", "A vault someone not connected shares: its name is not known here, said as its name; the line that it comes once accepted stands under it.", at(FakeScene.VAULTS, SignedInPage.SHARING) { api, _ ->
            api.script.strangerSharesVault("Mallory")
        })
        s(sharing, "people-answerer-compare", "People: Cy answered this account's link and Cy's code has not arrived yet: Compare codes is offered (it opens on the wait for that code).", at(FakeScene.VAULTS, SignedInPage.SHARING) { api, m ->
            val cy = requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).contacts.first { it.label == "Cy" }
            cy.codesReady = false
            cy.compared = false
            cy.revealWaiting = true
            m.run({ contacts.openContacts() })
        })
        fun family(api: FakeAppApi) = requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).vaults.first { it.name == "Family" }
        s(sharing, "vault-offered-to-you", "Work's owner, Bo, asked this account to become its owner: the line for the person offered, and Become the owner.", at(FakeScene.VAULTS, SignedInPage.SHARING) { api, _ ->
            val me = requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
            api.script.ownerOffersOwnership(me.vaults.first { it.name == "Work" }, 14)
        })
        s(sharing, "vault-offer-other-member", "A member of Family who is neither its owner nor the person offered: the line naming the person offered (never the owner's own note).", at(FakeScene.VAULTS, SignedInPage.SHARING) { api, m ->
            offerToAnotherMember(api, m)
            handOwnershipToSomeoneElse(api, family(api))
        })
        sh(FakeScene.PROMPTS, "What waits for an answer: an incoming vault, a new contact, and more.")
        sh(FakeScene.PROMPT_RECOVERY_KEY_CHANGED, "The prompt that the operator's recovery key changed.")
        sh(FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY, "The prompt to keep the operator's recovery.")
        sh(FakeScene.PROMPT_CONNECTION_NOT_MADE, "The prompt that a connection was not made.")
        sh(FakeScene.PEOPLE_LIST, "The people list after an account is made.")
        sh(FakeScene.CONTACTS, "People: contacts, compared or not.")
        sh(FakeScene.CONTACTS_NOT_REVIEWED, "People: the list was put off.")
        sh(FakeScene.COMPARE_WAITING, "Compare codes: waiting for the other person.")
        sh(FakeScene.COMPARE_READY, "Compare codes: both codes ready.")
        sh(FakeScene.COMPARE_LINK_FAILED, "Compare codes: the link failed.")
        sh(FakeScene.COMPARE_MATCHED, "Compare codes: they matched.")
        sh(FakeScene.LINKS, "Links and invitations: make one, the ones out.")
        sh(FakeScene.OPENED_CONNECT, "An opened link: connect with someone.")
        // An account made on another device: this phone keeps no name for its links, so it asks first.
        fun noNameHere(api: FakeAppApi) {
            requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).nameHere = null
        }
        s(sharing, "opened-connect-name-needed", "Connect on that link, on a phone whose account was made on another device: the name the other person will see is asked first; nothing was sent.", at(FakeScene.OPENED_CONNECT, SignedInPage.SHARING) { api, m ->
            noNameHere(api)
            m.linkAct(TrustModel.LinkAct.Connect(requireNotNull(api.snapshot.account?.opened as? io.silencelen.andvari.core.app.OpenedInvite.Connect)))
        })
        s(sharing, "links-name-needed", "Make a connect link on such a phone: the same question, over the sharing page.", at(FakeScene.LINKS, SignedInPage.SHARING) { api, m ->
            noNameHere(api)
            m.linkAct(TrustModel.LinkAct.MakeConnectLink(emptyList(), 60))
        })
        s(sharing, "links-name-not-a-name", "A name a link cannot carry (a space at its start): the question stays with its sentence, and what was typed is kept.", at(FakeScene.LINKS, SignedInPage.SHARING) { api, m ->
            noNameHere(api)
            m.linkAct(TrustModel.LinkAct.MakeConnectLink(emptyList(), 60))
            m.giveOwnName(" Ada")
        })
        sh(FakeScene.OPENED_KEY_CHANGED, "An opened link whose sender's key changed.")
        sh(FakeScene.OPENED_OTHER_INSTANCE, "An opened link for another server.")
        sh(FakeScene.OPENED_TRUST_GATE, "An enrol link for a server this phone never used: its Trust Gate.")
        s(sharing, "opened-trust-gate-confirmed", "That Trust Gate confirmed: both servers named, the sign-out line, Switch and Cancel.", at(FakeScene.OPENED_TRUST_GATE, SignedInPage.SHARING) { api, _ ->
            runBlocking { api.links.confirmOpenedGate(requireNotNull(api.snapshot.account?.opened as? io.silencelen.andvari.core.app.OpenedInvite.TrustGate)) }
        })
        s(sharing, "opened-other-instance-unsent", "An invite for another server while a change made here was not sent: how many are lost by switching, and \"try sending them first\".", at(FakeScene.OPENED_OTHER_INSTANCE, SignedInPage.SHARING) { api, _ ->
            val c = requireNotNull(api.fakeContent)
            c.setOffline(true)
            check(runBlocking { c.saveLogin(null, LoginInput("Bank", "ada", "pw-bank", listOf("https://bank.example"), "", "", false), null) } == ActionResult.Ok)
        })
        val otherInstance = { a: FakeAppApi -> requireNotNull(a.snapshot.account?.opened as? io.silencelen.andvari.core.app.OpenedInvite.OtherInstance) }
        s(sharing, "opened-other-instance-send-failed", "The invite for another server after \"try sending them first\" failed: its sentence on the screen, above Switch.", asking(FakeScene.OPENED_OTHER_INSTANCE, SignedInPage.SHARING, { it.offlineSave("Bank") }) { a, m -> m.switchAsk(otherInstance(a)).also { it.open(); it.sendFirst() } })
        s(sharing, "opened-other-instance-second", "Switch over a change not sent: the second confirmation, the line again, and the way back to the invite.", asking(FakeScene.OPENED_OTHER_INSTANCE, SignedInPage.SHARING, { it.offlineSave("Bank") }) { a, m -> m.switchAsk(otherInstance(a)).also { it.open(); it.confirm() } })
        s(sharing, "opened-other-instance-switched", "After Switch on an invite for another server: signed out here, the other server's entry screen.", at(FakeScene.OPENED_OTHER_INSTANCE, SignedInPage.SHARING) { api, _ ->
            runBlocking { api.links.switchInstance(requireNotNull(api.snapshot.account?.opened as? io.silencelen.andvari.core.app.OpenedInvite.OtherInstance)) }
        })
        s(sharing, "prompt-contact-key-changed", "A contact answered this account's link under a new key: the prompt, with Compare codes.", at(FakeScene.VAULTS, SignedInPage.SHARING) { api, _ ->
            contactAnswersUnderANewKey(api)
        })
        s(sharing, "prompt-contact-key-changed-compare", "Compare codes opened from that prompt on the vault's home page: a screen of its own, with this phone's code to read out and the field for theirs; a match replaces the key.", at(FakeScene.VAULTS, SignedInPage.VAULT) { api, _ ->
            val prompt = contactAnswersUnderANewKey(api)
            runBlocking { api.contacts.openCompareForNewKey(prompt) }
        })
        s(sharing, "prompt-contact-key-changed-compare-wrong", "The same comparison after a wrong code: the design's sentence, and the field to type again; nothing was replaced.", at(FakeScene.VAULTS, SignedInPage.VAULT) { api, m ->
            val prompt = contactAnswersUnderANewKey(api)
            runBlocking { api.contacts.openCompareForNewKey(prompt) }
            val ready = requireNotNull(api.snapshot.account?.comparing as? io.silencelen.andvari.core.app.CompareScreen.Ready)
            val wrong = (0..999_999).asSequence().map { it.toString().padStart(6, '0') }.first { it != ready.code && it != api.script.codeTheyReadOut(ready.userId) }
            m.runSaying({ contacts.submitComparison(ready, wrong) }, { r -> comparisonWords(m, ready, wrong, r) })
        })
        s(sharing, "prompt-contact-key-changed-compare-matched", "The same comparison after Dana's own code: the codes match, the new key is the one pinned, and the prompt is gone.", at(FakeScene.VAULTS, SignedInPage.VAULT) { api, m ->
            val prompt = contactAnswersUnderANewKey(api)
            runBlocking { api.contacts.openCompareForNewKey(prompt) }
            val ready = requireNotNull(api.snapshot.account?.comparing as? io.silencelen.andvari.core.app.CompareScreen.Ready)
            val theirs = requireNotNull(api.script.codeTheyReadOut(ready.userId))
            m.runSaying({ contacts.submitComparison(ready, theirs) }, { r -> comparisonWords(m, ready, theirs, r) })
        })
        sh(FakeScene.OPENED_SERVER_CHANGED, "An invite for another pinned server that moved since.")
        sh(FakeScene.OPENED_CONNECTED, "Connect answered: the invite names the contact it made.")
        sh(FakeScene.MEMBERS, "A shared vault's members.")
        sh(FakeScene.MEMBERS_MAY_BE_INCOMPLETE, "Members, when the list may be incomplete.")
        s(sharing, "vault-settings-owner", "A shared vault's own page, opened from its row's settings button: the owner's (Rename beside the name, members, delete).", vaultPage(FakeScene.VAULTS) { a -> a.vaults.first { it.name == "Family" }.vaultId })
        s(sharing, "vault-settings-writer", "A shared vault's own page for a writer: the role, members, save its items elsewhere, leave.", vaultPage(FakeScene.VAULTS) { a -> a.vaults.first { it.name == "Work" }.vaultId })
        s(sharing, "vault-settings-members", "The members, opened from the vault's own page.", vaultPage(FakeScene.MEMBERS) { a -> requireNotNull(a.members).vault.vaultId })
        s(sharing, "vault-settings-move-waiting", "A vault whose deletion by Move everything is signed and waiting: read-only on this device, said on its page.") {
            val api = api(FakeScene.VAULTS)
            val m = model(api)
            val family = requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).vaults.first { it.name == "Family" }
            family.moveUnfinishedInto = "Work"
            family.moveDeleteWaiting = true
            api.script.changed()
            m.onSnapshot(api.snapshot)
            Drawn(m, SignedInPage.SHARING, null, family.vaultId)
        }
        s(sharing, "move-stored-outside", "The server stored a move's deletion of the old vault outside the move: the notice, with its copy and its dismiss.") {
            val api = api(FakeScene.VAULTS)
            val m = model(api)
            val family = requireNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).vaults.first { it.name == "Family" }
            family.moveUnfinishedInto = "Work"
            family.moveDeleteWaiting = true
            api.script.changed()
            api.script.serverStoresMoveDeleteLater(added = 2, changed = 1)
            m.onSnapshot(api.snapshot)
            Drawn(m, SignedInPage.SHARING)
        }
        sh(FakeScene.SHARE_WARNING,"The warning before sharing with someone not compared.")
        sh(FakeScene.MOVE_EVERYTHING, "Move everything to a new vault.")
        sh(FakeScene.MOVE_EVERYTHING_FROZEN, "Move everything out of a frozen vault: tick who comes along.")

        val settings = "8 Settings"
        fun se(scene: FakeScene, caption: String) = s(settings, scene.name.lowercase().replace('_', '-'), caption, at(scene, SignedInPage.SETTINGS))
        s(settings, "settings", "Settings: the account, quick unlock, two-step, devices, recovery, password, autofill, deletion.", at(FakeScene.VAULTS, SignedInPage.SETTINGS))
        // What opens from Sign out (the rule of 2026-11-17 on changes not sent), drawn open at each step.
        val settingsSignOut = { prep: (FakeAppApi) -> Unit, walk: (SignOutAsk) -> Unit ->
            asking(FakeScene.VAULTS, SignedInPage.SETTINGS, prep) { _, m -> m.signOutAsk().also { it.open(); walk(it) } }
        }
        s(settings, "sign-out-confirm", "Sign out in Settings with nothing waiting: the one confirmation, as the current app's.", settingsSignOut({}) {})
        s(settings, "sign-out-confirm-unsent", "Sign out with two changes this phone has not sent: how many are lost, and \"try sending them first\".", settingsSignOut({ it.offlineSave("Bank"); it.offlineSave("Shop") }) {})
        s(settings, "sign-out-confirm-send-failed", "The same after \"try sending them first\" failed (the server does not answer): its sentence inside the confirmation.", settingsSignOut({ it.offlineSave("Bank"); it.offlineSave("Shop") }) { it.sendFirst() })
        s(settings, "sign-out-confirm-second", "The second confirmation over changes not sent: the line again, \"sign out anyway\", and the way out.", settingsSignOut({ it.offlineSave("Bank"); it.offlineSave("Shop") }) { it.confirm() })
        s(locked, "locked-sign-out-cannot-tell", "Sign out from the lock screen: this phone cannot tell what was not sent while locked, so it says so.", asking(FakeScene.VAULTS, null, { it.offlineSave("Bank"); it.lock() }) { _, m -> m.signOutAsk().also { it.open() } })
        // The autofill windows: each its own activity over another app, drawn as the activity draws it.
        val autofill = "Autofill windows"
        val bank = io.silencelen.andvari.core.client.autofill.AppFillGate.Identity("com.example.bank", "Example Bank", false, "com.android.vending", "ab".repeat(32), installerSystem = true)
        val sideloaded = io.silencelen.andvari.core.client.autofill.AppFillGate.Identity("com.example.notes", null, false, null, "cd".repeat(32))
        fun window(content: @androidx.compose.runtime.Composable () -> Unit): () -> Drawn = { Drawn(model(api(FakeScene.VAULTS)), window = content) }
        fun bake(identity: io.silencelen.andvari.core.client.autofill.AppFillGate.Identity, verdict: io.silencelen.andvari.core.client.autofill.AppFillGate.Verdict, installer: String?) =
            io.silencelen.andvari.app.autofill.AppFillBinding.Bake(identity, verdict, installer, "item-1")
        val confirm = io.silencelen.andvari.core.client.autofill.AppFillGate.Verdict.CONFIRM
        val changed = io.silencelen.andvari.core.client.autofill.AppFillGate.Verdict.CONFIRM_SIGNER_CHANGED
        s(autofill, "autofill-app-confirm", "Filling a login into an app for the first time: which app, from where, and the login.", window {
            io.silencelen.andvari.app.autofill.ConfirmCard(bake(bank, confirm, "Google Play Store"), io.silencelen.andvari.app.autofill.LoginLine("Example Bank", "ada@example.com"), true, {}, {})
        })
        s(autofill, "autofill-app-confirm-signer-changed", "The same app after its signer changed since the last fill.", window {
            io.silencelen.andvari.app.autofill.ConfirmCard(bake(bank, changed, "Google Play Store"), io.silencelen.andvari.app.autofill.LoginLine("Example Bank", "ada@example.com"), true, {}, {})
        })
        s(autofill, "autofill-app-confirm-sideloaded", "An app with no readable label and no installer.", window {
            io.silencelen.andvari.app.autofill.ConfirmCard(bake(sideloaded, confirm, null), io.silencelen.andvari.app.autofill.LoginLine("Notes", null), true, {}, {})
        })
        s(autofill, "autofill-card-confirm", "Filling a card into an app: which app and the card, masked.", window {
            io.silencelen.andvari.app.autofill.CardConfirmCard(bake(bank, confirm, "Google Play Store"), io.silencelen.andvari.app.autofill.CardLine("Everyday card", "•••• 1111"), true, {}, {})
        })
        s(autofill, "autofill-trust-browser", "A browser asking to fill for the first time: trust this browser?", window {
            io.silencelen.andvari.app.autofill.TrustCard("com.example.browser", bank.copy(pkg = "com.example.browser", label = "Example Browser"), "Google Play Store", io.silencelen.andvari.app.autofill.ApprovedBrowsers.Offer.FIRST_TIME, true, {}, {})
        })
        s(autofill, "autofill-trust-browser-signer-changed", "A browser trusted before whose signer changed: asked again, with the warning.", window {
            io.silencelen.andvari.app.autofill.TrustCard("com.example.browser", bank.copy(pkg = "com.example.browser", label = "Example Browser"), "Google Play Store", io.silencelen.andvari.app.autofill.ApprovedBrowsers.Offer.SIGNER_CHANGED, true, {}, {})
        })
        s(autofill, "autofill-unlock", "Autofill while the vault is locked: unlock with the master password, with the hint where quick unlock is switched on.", window {
            io.silencelen.andvari.app.autofill.UnlockCard("ada@example.com", false, null, true, null, {}, {})
        })
        s(autofill, "autofill-save-new", "A login typed into a site, offered to be saved: the site, the user name and the password unshown.", window {
            io.silencelen.andvari.app.autofill.SaveCard(io.silencelen.andvari.app.autofill.LoginPlan.New, "shop.example.com", "ada@example.com", false, null, {}, {})
        })
        s(autofill, "autofill-save-update", "A new password for a login already saved: the login it updates, by name and user name.", window {
            io.silencelen.andvari.app.autofill.SaveCard(io.silencelen.andvari.app.autofill.LoginPlan.Update("item-1", "The very long name of a login for a municipal water and electricity customer portal", "a.very.long.username.for.this.site@subdomain.example.com"), "portal.utilities.city.example", "a.very.long.username.for.this.site@subdomain.example.com", false, null, {}, {})
        })
        s(autofill, "autofill-save-card", "A card typed at a checkout, offered to be saved: brand and last four only.", window {
            io.silencelen.andvari.app.autofill.CardSaveCard(io.silencelen.andvari.app.autofill.CardPlan.New("Visa ••1111"), false, null, {}, {})
        })
        s(autofill, "autofill-save-unlock", "Saving while the vault is locked: unlock first, naming what is being saved.", window {
            io.silencelen.andvari.app.autofill.UnlockToSaveCard("ada@example.com", "a login for shop.example.com", false, null, {}, {})
        })
        s(autofill, "autofill-chooser", "Andvari's own list for an app with several logins: which app asks, then one line per login.", window {
            val gate = io.silencelen.andvari.app.autofill.AppFillBinding.AppGate(bank, confirm, "Google Play Store")
            val rows = listOf(
                io.silencelen.andvari.app.autofill.FillRow.Login<android.view.autofill.AutofillId>("item-1", "Example Bank", "ada@example.com", emptyList()),
                io.silencelen.andvari.app.autofill.FillRow.Login<android.view.autofill.AutofillId>("item-2", "Example Bank (joint account with a very long name)", "a.very.long.username.for.this.site@subdomain.example.com", emptyList()),
            )
            io.silencelen.andvari.app.autofill.ChooserList(io.silencelen.andvari.app.autofill.ChooserKind.LOGINS, gate, rows, emptyMap(), emptyMap(), {}, {})
        })
        s(locked, "locked-sign-out-second", "The second confirmation from the lock screen, over what this phone cannot count.", asking(FakeScene.VAULTS, null, { it.offlineSave("Bank"); it.lock() }) { _, m -> m.signOutAsk().also { it.open(); it.confirm() } })
        se(FakeScene.DEVICES, "Your devices.")
        se(FakeScene.HOST_LINK_SHOWN, "Linking a new device from this phone: the link shown.")
        se(FakeScene.HOST_LINK_CLAIMED, "Linking: the new device claimed the link.")
        se(FakeScene.HOST_LINK_TYPE_DIGITS, "Linking: type the digits the new device shows.")
        se(FakeScene.HOST_LINK_APPROVABLE, "Linking: approve with the master password.")
        fun approveWithCheck(api: FakeAppApi, m: TrustModel) {
            val host = requireNotNull(api.snapshot.account?.deviceLink as? io.silencelen.andvari.core.app.DeviceLinkHost.Approvable)
            m.runIn(io.silencelen.andvari.app.trust.DEVICE_LINK_SECTION, { devices.approveWithBiometrics(host, io.silencelen.andvari.app.trust.deviceApprovalReason(host)) }, { io.silencelen.andvari.app.trust.deviceLinkProofWords(it, 0) })
        }
        s(settings, "host-link-approvable-cancelled", "Linking: the fingerprint or face prompt was cancelled. Nothing was approved; the new device still waits, and the password or the check can approve it.", at(FakeScene.HOST_LINK_APPROVABLE, SignedInPage.SETTINGS) { api, m ->
            api.script.biometricsCancelled = true
            approveWithCheck(api, m)
        })
        s(settings, "host-link-approvable-check-not-used", "Linking: the fingerprint or face check can't be used now (a lockout, say): the master password approves.", at(FakeScene.HOST_LINK_APPROVABLE, SignedInPage.SETTINGS) { api, m ->
            api.script.biometricsRefused = true
            approveWithCheck(api, m)
        })
        se(FakeScene.HOST_LINK_APPROVED, "Linking: approved.")
        se(FakeScene.HOST_LINK_CANCELLED, "Linking: cancelled.")
        s(settings, "two-step-too-many-tries", "Two-step sign-in: too many tries, and the server names the wait: one sentence with the wait (never after a sentence that says the same).", at(FakeScene.VAULTS, SignedInPage.SETTINGS) { api, m ->
            // `this.settings`: the app interface's, not this group's name.
            m.run({ this.settings.openTwoStep() })
            m.run({ this.settings.startTwoStep(requireNotNull(api.snapshot.account?.twoStep), FakeScenes.PASSWORD) })
            m.run({ this.settings.confirmTwoStep(requireNotNull(api.snapshot.account?.twoStep?.enrolment), api.script.authenticatorCode) })
            api.script.twoStepTriesLocked = true
            m.runIn(io.silencelen.andvari.app.trust.TWO_STEP_SECTION, { this.settings.turnOffTwoStepWithPassword(requireNotNull(snapshot.account?.twoStep), "000000", FakeScenes.PASSWORD) }, { io.silencelen.andvari.app.trust.twoStepWords(it, 30) })
        })
        se(FakeScene.RECOVERY, "Recovery settings.")
        s(settings, "recovery-requests-live", "Recovery settings: two live requests for this account, which may be a stranger's: each row names its stage only (in its wait; waiting for the operator).", at(FakeScene.VAULTS, SignedInPage.SETTINGS) { api, m ->
            m.run({ recovery.openRecovery() })
            api.script.someoneAsksOperator(AppPlatform.IOS)
            requireNotNull(api.script.someoneAsksOperator(AppPlatform.ANDROID)).stage = io.silencelen.andvari.core.app.OperatorHelpStage.AWAITING_OPERATOR
            api.script.changed()
        })
        s(settings, "recovery-requests-unreadable", "Recovery settings: requests this device could not read, the two lines under the list.", at(FakeScene.VAULTS, SignedInPage.SETTINGS) { api, m ->
            m.run({ recovery.openRecovery() })
            api.script.requestListServed(unreadableRows = 2)
        })
        se(FakeScene.RECOVERY_WARNING_IN_SETTINGS, "Recovery settings: the warning before nobody else can recover.")
        se(FakeScene.KIT_IN_SETTINGS, "A new recovery kit from Settings.")
        se(FakeScene.DELETION, "Delete the account.")
        se(FakeScene.DELETION_BLOCKED, "Delete the account: blocked while you own shared vaults.")
        se(FakeScene.DELETION_OUTCOME_UNKNOWN, "Delete the account: the outcome of a deletion is not known yet.")

        val card = "9 The server's card"
        fun c(scene: FakeScene, caption: String) = s(card, scene.name.lowercase().replace('_', '-'), caption, at(scene, SignedInPage.VAULT))
        c(FakeScene.CARD_WITHHELD, "The server serves an older card.")
        c(FakeScene.CARD_STOPPED, "The server's identity forked: stopped.")
        c(FakeScene.CARD_DAMAGED, "The card on this phone is damaged.")
        c(FakeScene.CARD_NOT_VERIFIED, "The card cannot be verified.")
        c(FakeScene.CARD_MOVED, "The server moved: follow it.")
        c(FakeScene.CARD_MOVE_ALREADY_PINNED, "A move to an address this phone already holds.")
        c(FakeScene.CARD_KIND_CHANGED, "The server's kind changed.")
        c(FakeScene.CARD_KIND_CHANGE_PUT_OFF, "The kind change, put off.")
        c(FakeScene.CARD_UPDATE_ANDVARI, "The server needs a newer andvari.")
    }
}
