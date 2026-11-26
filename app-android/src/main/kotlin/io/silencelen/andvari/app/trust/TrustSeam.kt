package io.silencelen.andvari.app.trust

import android.content.Context
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.silencelen.andvari.app.AndroidBellSocket
import io.silencelen.andvari.app.AndroidClocks
import io.silencelen.andvari.app.androidHttpClient
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.app.engine.SqliteVaultCacheFiles
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.DeviceStateFile
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.net.Dialer
import io.silencelen.andvari.core.client.pin.BakedInstance
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The one process-wide app API of the new path (the old path's `VaultSession` is process-wide the same way): the
 * engine-backed [AppApi] built from this platform's stores, HTTP stack and build constants, and the [TrustModel] the
 * activity renders. It shares nothing with the old path's `SessionStore`, `VaultSession` or autofill service.
 */
object TrustSeam {
    @Volatile private var built: TrustModel? = null
    @Volatile private var wrap: AndroidKeyWrap? = null

    fun model(context: Context): TrustModel = built ?: synchronized(this) {
        built ?: build(context.applicationContext).also { built = it }
    }

    /** The one save queue of this process (the content reads it; the autofill service adds to it). */
    internal fun saveQueue(context: Context): AndroidSaveQueue = queue ?: synchronized(this) {
        queue ?: AndroidSaveQueue(File(context.applicationContext.noBackupFilesDir, "ovh/save-queue")).also { queue = it }
    }

    @Volatile private var queue: AndroidSaveQueue? = null

    /** The crypto the engine was built with, for sealing a capture to the published key. */
    internal fun crypto(context: Context): io.silencelen.andvari.core.crypto.CryptoProvider {
        model(context)
        return cryptoBuilt!!
    }

    @Volatile private var cryptoBuilt: io.silencelen.andvari.core.crypto.CryptoProvider? = null

    /** Quick unlock's platform key; the activity attaches itself so the prompt can be shown over it. */
    internal fun keyWrap(context: Context): AndroidKeyWrap {
        model(context)
        return wrap!!
    }

    private fun build(app: Context): TrustModel {
        val keyWrap = AndroidKeyWrap(app).also { wrap = it }
        val dir = File(app.noBackupFilesDir, "ovh").apply { mkdirs() }
        val http = androidHttpClient()
        val state = JsonDeviceState(PlainStateFile(File(dir, "device-state.json")))
        // The only public way to open a client: the Dialer carries the guard that stops all traffic to a server
        // whose identity failed. It reads the same pin store as the engine's CardTrust (the engine's `state`).
        // The event bell's socket is the app's own (OkHttp cannot bound a message before it holds it): the dialer
        // still decides whether and where it opens; AndroidBellSocket carries the frames, bounded.
        val bellSocket = AndroidBellSocket.forApp()
        val dialer = Dialer(PinStore(state), http, AppPlatform.ANDROID.wireName, bellSocket = bellSocket)
        val secureFile = KeystoreSealedFile(File(dir, "secure-state.bin"))
        val crypto = createCryptoProvider().also { cryptoBuilt = it }
        val api: AppApi = EngineAppApi(
            AppEngine(
                platform = AppPlatform.ANDROID,
                deviceName = checkedDeviceName(android.os.Build.MODEL),
                // Every client, and the event bell's socket, from the one dialer and its guard (a transport made as
                // `WireTransport(dialer::open)` has no bell).
                transport = dialingTransport(dialer),
                state = state,
                secure = JsonDeviceState(secureFile),
                crypto = crypto,
                clock = { System.currentTimeMillis() },
                baked = bakedInstance(),
                storeBuild = true,
                stores = NoOldStores,
                // The engine's own scope runs the opening's sync, a ring's sync, the save queue and the end of a session.
                // Its scope has no handler of its own (EngineAppApi's scope), so an exception
                // that escapes there would end the process. The app hands it one with its main thread: a fault is
                // contained and said above the screen; nothing of it is kept.
                main = Dispatchers.Main.immediate + AppFaults.handler(),
                keyWrap = keyWrap,
                // Quick unlock exists in core only with the platform's clocks (its freshness rule reads the monotonic
                // clock and the boot identity); without them it is never offered.
                clocks = AndroidClocks,
                // A followed server move takes this app's per-(server, account) folders with it (design §4.4).
                namespaceMover = AndroidNamespaceMover(dir),
                // The vault's offline copy, as SQLite files in app-private, no-backup storage beside the device state.
                // Core decides per session whether a file may be kept at all (the policy's offlineCacheAllowed). The
                // rename never replaces a file, so a followed move carries the copy to the new address's names.
                cacheFiles = SqliteVaultCacheFiles(
                    File(dir, "vault-cache").apply { mkdirs() }.absolutePath,
                    AppFiles::moveWithoutReplacing,
                    AppFiles::remove,
                ),
                // What a lock cut short (a move, a save with files, the applied saves), made once for the process over
                // app-private files; core keeps them as files only while the policy allows an offline copy.
                // The save queue the autofill service seals captures into (AutofillSave), read by the content at
                // every unlock, sync and return to the foreground; emptied with the kept records at the person's end.
                contentStores = ContentStores(crypto, AndroidKeptStorage(File(dir, "kept")), saveQueue(app)),
            ),
        ).also { engine ->
            // The engine's diagnostics, before its start (the sweep runs there): into this phone's technical log, by their
            // code only (EngineDiagnostics says why).
            engine.diagnostics = io.silencelen.andvari.app.EngineDiagnostics.sink(app.filesDir, { io.silencelen.andvari.app.autofill.AutofillDebugLog.debugEnabled(app) })
        }
        // Started where it is built: the autofill service and its activities can
        // be the first to reach the API after a cold start, and nothing in the API works before start(). start() is
        // idempotent, so MainActivity's own call finds it started. The model comes first, so a fault in the start's own
        // work is said by it.
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate + AppFaults.handler())
        val model = TrustModel(api, scope, BuildConstants.JOIN_BASE, { SystemClock.elapsedRealtime() }, { secureFile.unreadable }, secureFile::newSessionWritten, AndroidAutofillRecords(app))
        // Where a contained fault with no answer in place is said: this process's one model.
        AppFaults.sink = model::fault
        model.start()
        // Live updates come back within seconds of the network: the platform's network notices
        // end a bell socket on a network that went away, and ask the bell to dial again when one is there (at most once
        // every 30 s). The bell is told with the shared code's own call for it
        // (networkReturned): live updates alone, in the foreground and the background alike; nothing else is read or
        // synced, so the save queue is no longer read on a network's return as the foreground call read it.
        io.silencelen.andvari.app.BellNetworkWatch.register(app, bellSocket) {
            model.networkReturned()
        }
        return model
    }

    /**
     * The public instance this build bakes (§0.3), or null while spec/public-instance.json holds placeholders: then
     * nothing is baked and the first screen offers no "Create an account on andvari".
     *
     * `storeBuild` is true in every build of this app (debug included), the safer reading: a build never follows a
     * move or `kind` change of the baked instance (§4.4, T-R7). With nothing baked it changes nothing.
     */
    internal fun bakedInstance(): BakedInstance? =
        if (BuildConstants.BAKES_PUBLIC_INSTANCE) {
            BakedInstance(BuildConstants.PUBLIC_ORIGIN, BuildConstants.PUBLIC_INSTANCE_ID, BuildConstants.PUBLIC_CARD0_HASH, BuildConstants.PUBLIC_KIND)
        } else {
            null
        }
}

/** Note 11: the autofill records [TrustModel] ends, in their preference files; the owner is the account they were made under. */
/**
 * The name this phone gives itself to the server: the phone's model, when the server's `text` rule takes it
 * ([io.silencelen.andvari.core.trust.TrustGrammar.isText]), else "Android". A model name holding a character the server
 * refuses would otherwise be refused at sign-in and at every device link with `400 bad_device`.
 */
internal fun checkedDeviceName(model: String?): String =
    model?.takeIf(io.silencelen.andvari.core.trust.TrustGrammar::isText) ?: "Android"

internal class AndroidAutofillRecords(private val app: Context) : AutofillRecords {
    private val prefs get() = app.getSharedPreferences("andvari_autofill_owner", Context.MODE_PRIVATE)

    override fun clear() {
        io.silencelen.andvari.app.autofill.ApprovedBrowsers.clearAll(app)
        io.silencelen.andvari.app.autofill.AppSignerBindings.clearAll(app)
        prefs.edit().clear().apply()
    }

    override fun forgetFills() = io.silencelen.andvari.app.autofill.AutofillDebugLog.forget(app)

    override fun owner(): String? = prefs.getString("accountId", null)

    override fun setOwner(accountId: String) {
        prefs.edit().putString("accountId", accountId).apply()
    }
}

/**
 * §12.4 on Android: this app installs under a new application id and so starts empty. The old app's stores belong to
 * the old package, which stays installed as the fallback device until it is uninstalled. There is nothing to delete
 * and nothing to report.
 */
internal object NoOldStores : PreCutoverStores {
    override fun wipe(store: PreCutoverStore): Boolean = true
}

/** A whole-file [DeviceStateFile] in app-private, no-backup storage, replaced atomically. Device state: pins, records. */
internal class PlainStateFile(file: File) : DeviceStateFile {
    private val atomic = AtomicFile(file)

    override fun read(): String? = try {
        String(atomic.readFully(), Charsets.UTF_8)
    } catch (e: FileNotFoundException) {
        null
    }

    override fun replace(text: String) {
        val out = atomic.startWrite()
        try {
            out.write(text.toByteArray(Charsets.UTF_8))
            atomic.finishWrite(out)
        } catch (e: Throwable) {
            atomic.failWrite(out)
            throw e
        }
    }
}

/**
 * The session-grade store (the engine's `secure`): the session's tokens and an operator-help request key, sealed with
 * AES-256-GCM under a non-exportable Android Keystore key, in app-private no-backup storage. The old app kept its
 * tokens in plain SharedPreferences; this is the new path's Keystore-backed replacement.
 *
 * A file that is there but cannot be opened is "unknown", never "no session": the
 * logic is [SealedStateFile]'s. A key store that does not answer is asked again; a copy that could not be opened is
 * set aside whole and read back when the key store answers again; and the first screen says the saved sign-in cannot
 * be read now ([TrustModel.savedSignInUnreadable]) instead of being silent. Core cannot yet take a throwing read as
 * "unknown" (it would not start), so until it can, it is handed "nothing" while the copy waits aside.
 */
internal class KeystoreSealedFile private constructor(private val inner: SealedStateFile) : DeviceStateFile by inner {
    constructor(file: File) : this(
        SealedStateFile(AtomicBytes(file), AtomicBytes(File(file.parentFile, file.name + ".unreadable")), KeystoreSealer, pause = { Thread.sleep(50L * it) }),
    )

    /** A copy is set aside because it could not be opened (the first screen says so). */
    val unreadable: Boolean get() = inner.unreadable

    /** A new session was written and opened: the copy set aside has been replaced and goes. */
    fun newSessionWritten() = inner.newSessionWritten()
}

/** One file in app-private, no-backup storage, replaced atomically. */
internal class AtomicBytes(private val file: File) : BytesFile {
    private val atomic = AtomicFile(file)

    override fun read(): ByteArray? = try {
        atomic.readFully()
    } catch (e: FileNotFoundException) {
        null
    }

    override fun write(bytes: ByteArray) {
        val out = atomic.startWrite()
        try {
            out.write(bytes)
            atomic.finishWrite(out)
        } catch (e: Throwable) {
            atomic.failWrite(out)
            throw e
        }
    }

    override fun delete() = atomic.delete()

    override val exists: Boolean get() = file.isFile
}

/**
 * AES-256-GCM under a non-exportable Android Keystore key. Opening never makes a key: a key that is not there is gone
 * ([KeyGone]), and making a new one under the same alias would end any chance of the old one answering again. Only
 * [seal] makes the key, the first time something is written.
 */
internal object KeystoreSealer : Sealer {
    private fun existingKey(): SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getKey(ALIAS, null) as? SecretKey
    }

    private fun key(): SecretKey {
        existingKey()?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    override fun seal(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, key())
        val iv = c.iv
        val ct = c.doFinal(plain)
        plain.fill(0)
        return byteArrayOf(VERSION, iv.size.toByte()) + iv + ct
    }

    /**
     * [KeyGone] for what asking again cannot change: bytes this app did not make, no key under the alias, a key the
     * store says it cannot recover, or a tag that does not verify (the key is not the one that sealed it). Anything
     * else (the key store busy or not answering) is thrown as it is, and the caller asks again.
     */
    override fun open(sealed: ByteArray): ByteArray {
        if (sealed.size <= 2 || sealed[0] != VERSION || sealed[1].toInt() !in 1..(sealed.size - 2)) throw KeyGone()
        val ivLen = sealed[1].toInt()
        val iv = sealed.copyOfRange(2, 2 + ivLen)
        val key = try {
            existingKey()
        } catch (e: java.security.UnrecoverableKeyException) {
            throw KeyGone(e)
        } ?: throw KeyGone()
        val c = Cipher.getInstance(TRANSFORM)
        try {
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            return c.doFinal(sealed, 2 + ivLen, sealed.size - 2 - ivLen)
        } catch (e: javax.crypto.AEADBadTagException) {
            throw KeyGone(e)
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw KeyGone(e)
        }
    }

    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "andvari.ovh.secure-state"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val VERSION: Byte = 1
}
