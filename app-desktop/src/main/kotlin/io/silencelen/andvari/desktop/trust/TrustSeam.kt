package io.silencelen.andvari.desktop.trust

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.pin.BakedInstance
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob

/**
 * The new path's composition root on desktop: the engine-backed [DesktopAppApi] built from this computer's stores
 * ([DesktopHome]), the JVM's HTTP client and the build's constants, and the [TrustModel] the window renders. It shares
 * nothing with the old path's `DesktopState` or `DesktopSessionStore`.
 */
object TrustSeam {
    fun model(home: DesktopHome = DesktopHome()): TrustModel {
        val platform = desktopPlatform()
        val state = JsonDeviceState(home.stateFile())
        val faults = BackgroundFaults()
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = platform,
                deviceName = deviceName(),
                // The only public way to open a client: the engine's Dialer over the pin store in [state], which stops all
                // traffic to a server whose identity failed (design §4.4).
                transport = dialingTransport(state, httpClient(), platform),
                state = state,
                secure = JsonDeviceState(home.secureFile),
                // Assisted recovery's requests survive a restart whatever "keep me signed in" says (requestStore).
                requestStore = JsonDeviceState(home.requestFile),
                crypto = createCryptoProvider(),
                clock = { System.currentTimeMillis() },
                baked = bakedInstance(),
                // Not a store build. The desktop follows a move or a kind change with the design's prompts.
                storeBuild = false,
                stores = DesktopOldStores(home.root),
                // Not Dispatchers.Main: this app has no module that provides it (see SwingMain). With the desktop's
                // handler: the engine's own scope is built over this context, and what
                // escapes there is said as "something went wrong", never an error nobody handles.
                main = SwingMain + faults.handler,
                cacheFiles = home.cacheFiles,
                contentStores = home.content.stores,
                // "Keep me signed in on this computer" is the platform's consent to a copy at rest; a switch that could
                // not be read is no consent. When it goes off, core is told before any file is deleted.
                keepsAtRest = home::keepsAtRest,
            ),
        )
        // Before the engine starts: its sweep at the start may say something.
        api.diagnostics = engineDiagnostics
        home.consentWithdrawn = api::atRestConsentChanged
        val scope = CoroutineScope(SupervisorJob() + SwingMain + faults.handler)
        // Both clocks: nanoTime stops while a Linux computer sleeps, the wall clock does not.
        return TrustModel(api, scope, { System.nanoTime() / 1_000_000 }, HomeSignInKeeping(home), wallMs = { System.currentTimeMillis() })
            .also { faults.model = it }
    }

    /**
     * Where the engine's diagnostics go ([io.silencelen.andvari.core.app.engine.EngineAppApi.diagnostics]): the desktop's
     * own technical log, one line each ([engineDiagnosticLine]). A line that cannot be written is let go: a diagnostic
     * never stops the engine.
     */
    internal val engineDiagnostics: CoreLog = CoreLog { event, detail ->
        runCatching { io.silencelen.andvari.desktop.DesktopDiagnostics.log(engineDiagnosticLine(event, detail)) }
    }

    /**
     * One diagnostic of the engine as the log keeps it: the event's code, and of its detail only what holds nothing of a
     * person's. The engine emits two today, both from its sweep of the records of accounts this device no longer knows
     * ([CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK]: it removed nothing, the store's keys or a record could not be read;
     * [CoreLog.EVENT_ACCOUNT_SWEEP_STOPPED]: the store refused a removal). Their detail names the record's key, which holds
     * an account's id and its server's address: only the kind of record (the key's first part) is written.
     */
    internal fun engineDiagnosticLine(event: String, detail: String): String {
        val code = event.filter { it.isLetterOrDigit() || it == '_' }.take(64).ifEmpty { "unnamed" }
        val what = Regex("ovh\\.[a-z]+\\|").find(detail)?.value?.let { "record $it…" }
            ?: if (detail.contains("the store's keys")) "the store's keys" else null
        return "engine: $code" + (what?.let { " ($it)" } ?: "")
    }

    /**
     * The handler of the engine's scope and the model's (the app's own scope once had no handler
     * for an exception that escapes): what reaches it goes to [TrustModel.faultedInBackground] on the window's thread,
     * which says it as "something went wrong" and logs the class name only. Before the model exists, the class name
     * is logged and nothing else.
     */
    internal class BackgroundFaults(private val onWindowThread: (Runnable) -> Unit = { java.awt.EventQueue.invokeLater(it) }) {
        @Volatile
        var model: TrustModel? = null

        val handler: CoroutineExceptionHandler = CoroutineExceptionHandler { _, t ->
            val m = model
            if (m == null) {
                runCatching { io.silencelen.andvari.desktop.DesktopDiagnostics.log("something went wrong :: ${t.javaClass.simpleName}") }
            } else {
                onWindowThread(Runnable { m.faultedInBackground(t) })
            }
        }
    }

    /**
     * The public instance this build bakes (§0.3), or null while spec/public-instance.json holds placeholders: then
     * nothing is baked and the first screen offers no "Create an account on andvari".
     */
    internal fun bakedInstance(): BakedInstance? =
        if (BuildConstants.BAKES_PUBLIC_INSTANCE) {
            BakedInstance(BuildConstants.PUBLIC_ORIGIN, BuildConstants.PUBLIC_INSTANCE_ID, BuildConstants.PUBLIC_CARD0_HASH, BuildConstants.PUBLIC_KIND)
        } else {
            null
        }

    /** The platform from the JVM's OS: the desktop builds for Windows and Linux only (macOS is not built). */
    internal fun desktopPlatform(os: String = System.getProperty("os.name").orEmpty()): AppPlatform =
        if (os.lowercase().contains("win")) AppPlatform.WINDOWS else AppPlatform.LINUX

    /** The name the devices list shows: the computer's name where the OS gives one, else the old app's "<OS> desktop". */
    internal fun deviceName(): String =
        (System.getenv("COMPUTERNAME") ?: System.getenv("HOSTNAME"))?.trim()?.takeIf { it.isNotEmpty() }
            ?: "${System.getProperty("os.name")} desktop"

    /**
     * The one HTTP client the engine's transport uses. It follows no redirect, in ktor or in the JDK client under it: a
     * 3xx reaches core as the answer it is, and nothing is asked of the address it names. (The update check has its own
     * client and its one closed rule for a redirect, [io.silencelen.andvari.desktop.fetchUpdateFile].)
     */
    internal fun httpClient(): HttpClient = HttpClient(Java) {
        install(HttpTimeout) { requestTimeoutMillis = 60_000; connectTimeoutMillis = 10_000 }
        expectSuccess = false
        followRedirects = false
        engine { config { followRedirects(java.net.http.HttpClient.Redirect.NEVER) } }
    }
}

/** Keeping the sign-in on this computer, as Settings switches it. */
interface SignInKeeping {
    val on: Boolean

    /** The switch's settings file could not be read: it is neither on nor off, and nothing kept is touched. */
    val unknown: Boolean get() = false

    /** The account (its account ID) the switch belongs to, or null. */
    val keptFor: String? get() = null

    /** Switch it; [account] is the account it belongs to while on. */
    fun set(on: Boolean, account: String?)

    /** The person's answer to the question an unreadable settings file raised. */
    fun answerUnknown(on: Boolean, account: String?) = set(on, account)

    /**
     * Whether this computer's key store can wrap the kept session now (note N2). False means the switch asks first: a
     * file only your account can read, or not kept.
     */
    fun keyStoreReady(): Boolean = true

    /** Kept, but the key store gave no key and the person has not chosen a plain file: they are asked. */
    val choiceNeeded: Boolean get() = false

    /** The kept session is wrapped and could not be opened: nothing was deleted, and the person signs in again. */
    val keptUnopenable: Boolean get() = false

    /** The person's answer where there is no key store: keep the sign-in in a file only their account can read. */
    fun keepInPlainFile(account: String?) = set(true, account)

    /**
     * What core keeps still names a session. A person's act that ended elsewhere (another server forgotten, which takes
     * the engine to the first screen while its session stays) is then not the end of the account kept here.
     */
    val sessionKept: Boolean get() = false

    /** Another account than the one the switch belongs to is open ([on]), or no longer: see [DesktopHome.setForeign]. */
    fun foreign(on: Boolean) {}

    /**
     * Assisted recovery's request is held in memory only (this computer's key store gave no key for `assist-requests.json`),
     * so it lasts for this run only.
     */
    val assistRequestThisRunOnly: Boolean get() = false

    /** Nothing is ever kept on disk (tests, previews). */
    object Never : SignInKeeping {
        override val on: Boolean get() = false

        override fun set(on: Boolean, account: String?) {}
    }
}

internal class HomeSignInKeeping(private val home: DesktopHome) : SignInKeeping {
    override val on: Boolean get() = home.prefs.keep() == Keep.ON

    override val unknown: Boolean get() = home.prefs.keep() == Keep.UNKNOWN

    override val keptFor: String? get() = home.prefs.keptFor

    override fun set(on: Boolean, account: String?) = home.setKeepSignIn(on, account)

    override fun answerUnknown(on: Boolean, account: String?) = home.answerUnreadablePrefs(on, account)

    override fun keyStoreReady(): Boolean = home.secureFile.keyStoreReady()

    override val choiceNeeded: Boolean get() = home.secureFile.choiceNeeded

    override val keptUnopenable: Boolean get() = home.secureFile.form == KeptForm.UNOPENABLE

    override fun keepInPlainFile(account: String?) = home.setKeepSignIn(true, account, plainFile = true)

    override val sessionKept: Boolean get() = home.secureFile.holdsSession

    override fun foreign(on: Boolean) = home.setForeign(on)

    override val assistRequestThisRunOnly: Boolean get() = home.requestFile.heldInMemoryOnly
}
