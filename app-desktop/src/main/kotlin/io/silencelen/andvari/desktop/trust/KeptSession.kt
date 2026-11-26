package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.client.DeviceStateFile
import io.silencelen.andvari.core.client.session.SessionKeeper
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.io.File
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The wrapped form of `secure-state.json`. The session's text is sealed with AES-256-GCM
 * under a key of its own; that key is kept by the operating system's key store ([OsKeyStore]) and the file carries
 * only the store's handle for it. The file is a JSON object of strings, so the start's damaged-file check
 * ([StateFiles]) reads its shape as it reads a plain one.
 *
 * `{"andvari.wrap":"2","store":"dpapi","handle":…,"account":…,"origin":…,"nonce":…,"sealed":…}`: the store's id, the
 * handle, and the account and server the session is for ([KeptBinding]) are bound into the
 * seal, so a file cannot be pointed at another key or another store, nor be taken for another account's or another
 * server's, without failing to open. A file of version 1 (an earlier build: store and handle bound, not the account)
 * still opens, and is sealed again as version 2 at once ([SignInStoreFile]).
 */
internal object SessionWrap {
    private const val MARK = "andvari.wrap"
    private const val VERSION = "2"
    private const val VERSION_1 = "1"
    private val json = Json { ignoreUnknownKeys = true }
    private val codec = MapSerializer(String.serializer(), String.serializer())
    private val list = ListSerializer(String.serializer())
    private val random = SecureRandom()
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private val unb64 = Base64.getUrlDecoder()

    /**
     * The account and the server [plain] (the engine's secure store, a JSON map) is for: core's kept session
     * ([SessionKeeper.KEY]) names its user ID and origin. Empty where it names none (no session in it yet).
     */
    fun bindingOf(plain: String): KeptBinding {
        val m = runCatching { json.decodeFromString(codec, plain) }.getOrNull() ?: return KeptBinding.NONE
        val s = m[SessionKeeper.KEY]?.let { runCatching { json.parseToJsonElement(it).jsonObject }.getOrNull() } ?: return KeptBinding.NONE
        fun str(name: String) = (s[name] as? JsonPrimitive)?.takeIf { it.isString }?.content.orEmpty()
        return KeptBinding(str("userId"), str("origin"))
    }

    /** The handle a wrapped file of [store] carries, or null (another store, not wrapped, no handle). Reads nothing sealed. */
    fun handleOf(text: String, store: KeyStoreKind): ByteArray? {
        val m = runCatching { json.decodeFromString(codec, text) }.getOrNull() ?: return null
        if (!m.containsKey(MARK) || m["store"] != store.id) return null
        return m["handle"]?.let { runCatching { unb64.decode(it) }.getOrNull() }
    }

    /** Whether [plain] (the engine's secure store) holds core's kept session. */
    fun namesASession(plain: String): Boolean = runCatching { json.decodeFromString(codec, plain) }.getOrNull()?.containsKey(SessionKeeper.KEY) == true

    /** The text is a wrapped file (whatever its version), not a session kept unwrapped by an earlier build. */
    fun isWrapped(text: String): Boolean = runCatching { json.decodeFromString(codec, text) }.getOrNull()?.containsKey(MARK) == true

    /** Seals [plain] for the account and server it names ([bindingOf]). */
    fun seal(plain: String, key: ByteArray, store: KeyStoreKind, handle: ByteArray): String = seal(plain, key, store, handle, VERSION)

    /** The earlier build's seal (version 1: store and handle bound, not the account): for the migration's tests only. */
    internal fun sealVersion1(plain: String, key: ByteArray, store: KeyStoreKind, handle: ByteArray): String = seal(plain, key, store, handle, VERSION_1)

    private fun seal(plain: String, key: ByteArray, store: KeyStoreKind, handle: ByteArray, version: String): String {
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val bytes = plain.encodeToByteArray()
        val binding = if (version == VERSION) bindingOf(plain) else null
        try {
            val sealed = cipher(Cipher.ENCRYPT_MODE, key, nonce, aad(version, store.id, handle, binding)).doFinal(bytes)
            val fields = linkedMapOf(MARK to version, "store" to store.id, "handle" to b64.encodeToString(handle))
            binding?.let {
                fields["account"] = it.account
                fields["origin"] = it.origin
            }
            fields["nonce"] = b64.encodeToString(nonce)
            fields["sealed"] = b64.encodeToString(sealed)
            return json.encodeToString(codec, fields)
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * What [open] found: the session's text, the key and handle it was sealed under (kept for the next write), and
     * whether it was sealed the old way ([oldSeal]: version 1, to be sealed again binding the account).
     */
    class Opened(val plain: String, val key: ByteArray, val handle: ByteArray, val oldSeal: Boolean = false)

    /**
     * Opens a wrapped file with [store]. Throws [KeyStoreUnavailable] when the store cannot give the key back, and
     * [WrapUnopenable] when the file is of another store or version, its seal does not hold, or it is for another
     * account or server than [expected] (this computer's record of what the kept file is for; null when there is none).
     * The account and server the file names are bound into its seal, so they cannot be changed in the file to pass.
     */
    fun open(text: String, store: OsKeyStore, expected: KeptBinding? = null): Opened {
        val m = runCatching { json.decodeFromString(codec, text) }.getOrNull() ?: throw WrapUnopenable("the wrapped file does not parse")
        val version = m[MARK]
        if (version != VERSION && version != VERSION_1) throw WrapUnopenable("the wrapped file is of another version")
        if (m["store"] != store.kind.id) throw WrapUnopenable("the file was wrapped by another key store (${printable(m["store"])})")
        val binding = if (version == VERSION) KeptBinding(m["account"] ?: throw WrapUnopenable("the wrapped file names no account"), m["origin"] ?: throw WrapUnopenable("the wrapped file names no server")) else null
        if (binding != null && expected != null && binding != expected) throw WrapUnopenable("the wrapped file is for another account or server")
        val handle = field(m, "handle")
        val nonce = field(m, "nonce")
        val sealed = field(m, "sealed")
        val key = store.recall(handle)
        val plain = try {
            cipher(Cipher.DECRYPT_MODE, key, nonce, aad(version, store.kind.id, handle, binding)).doFinal(sealed)
        } catch (e: Exception) {
            key.fill(0)
            throw WrapUnopenable("the wrapped file's seal does not hold")
        }
        try {
            val opened = Opened(plain.decodeToString(), key, handle, oldSeal = version == VERSION_1)
            // Sealed by whoever holds the key, so it names what it is for; checked all the same.
            if (binding != null && bindingOf(opened.plain) != binding) {
                key.fill(0)
                throw WrapUnopenable("the wrapped file's session is for another account or server than it names")
            }
            return opened
        } finally {
            plain.fill(0)
        }
    }

    private fun field(m: Map<String, String>, name: String): ByteArray =
        m[name]?.let { runCatching { unb64.decode(it) }.getOrNull() } ?: throw WrapUnopenable("the wrapped file has no $name")

    /** Version 1's associated data as it was; version 2's as a JSON list, so no field can run into the next. */
    private fun aad(version: String, store: String, handle: ByteArray, binding: KeptBinding?): ByteArray =
        if (version == VERSION_1) {
            "andvari-desktop kept session $VERSION_1\n$store\n${b64.encodeToString(handle)}".encodeToByteArray()
        } else {
            val b = binding ?: KeptBinding.NONE
            json.encodeToString(list, listOf("andvari-desktop kept session", VERSION, store, b64.encodeToString(handle), b.account, b.origin)).encodeToByteArray()
        }

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray): Cipher {
        if (key.size != KEY_BYTES) throw WrapUnopenable("the key store gave back a key of the wrong size")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
        }
    }

    const val KEY_BYTES = 32

    fun newKey(): ByteArray = ByteArray(KEY_BYTES).also { random.nextBytes(it) }
}

/** A wrapped file that cannot be opened for what it is (another store, another version, a seal that does not hold). */
class WrapUnopenable(message: String) : Exception(message)

/** The account (core's user ID) and the server (its origin) a kept session is for; empty strings where it names none. */
data class KeptBinding(val account: String, val origin: String) {
    companion object {
        val NONE = KeptBinding("", "")
    }
}

/** This computer's record of what the kept file is for ([DesktopTrustPrefs]): read before it is opened, written at each seal. */
interface BindingRecord {
    fun expected(): KeptBinding?

    fun record(binding: KeptBinding)

    object None : BindingRecord {
        override fun expected(): KeptBinding? = null

        override fun record(binding: KeptBinding) {}
    }
}

/**
 * Text read from a file or given by a key store, made safe for one line of the diagnostic log:
 * control characters and line separators are escaped, so a file's writer cannot forge log lines, and it is cut
 * to [max] characters.
 */
internal fun printable(s: String?, max: Int = 120): String {
    if (s == null) return "none"
    val out = StringBuilder()
    for (c in s.take(max)) {
        when {
            c == '\n' -> out.append("\\n")
            c == '\r' -> out.append("\\r")
            c == '\t' -> out.append("\\t")
            c == '\\' -> out.append("\\\\")
            c.isISOControl() || c == '\u2028' || c == '\u2029' || Character.getType(c) == Character.FORMAT.toInt() ->
                out.append("\\u").append(c.code.toString(16).padStart(4, '0'))
            else -> out.append(c)
        }
    }
    if (s.length > max) out.append("…")
    return out.toString()
}

/** What `secure-state.json` holds, as this run found it and has kept it since. */
enum class KeptForm {
    /** No kept session on disk. */
    NONE,

    /** Wrapped by this computer's key store. */
    WRAPPED,

    /** Unwrapped: an earlier build's file accepted as its migration, or the person's choice on a computer with no key store. */
    PLAIN,

    /**
     * It could not be opened: wrapped, and the key store is missing, refused, or holds no such key, or the file is of
     * another store; or unwrapped where the person never chose that and it is not the earlier build's migration.
     * Unknown, never "nothing kept": nothing reads as a session, nothing deletes it, and the
     * person is asked to sign in again. When the reason is the file itself (or a key store that answers but no longer
     * holds its key), the first new session to be kept moves it aside under a new name, unread; a key store that does
     * not answer never has it moved (D4). What was set aside goes with the switch.
     */
    UNOPENABLE,
}

/**
 * An unwrapped `secure-state.json` is accepted without the person's choice only once, as the
 * migration of an earlier build that did not wrap ([DesktopTrustPrefs] keeps the record).
 */
interface PlainMigration {
    /** Whether [text], an unwrapped file, is the earlier build's migration (recorded at [now] the first time); else false. */
    fun accept(text: String, now: Long): Boolean

    /** The migrated file was wrapped, replaced by the person's choice, or removed: nothing unwrapped is accepted again. */
    fun done()

    /** No migration: an unwrapped file is accepted only by the person's choice. */
    object None : PlainMigration {
        override fun accept(text: String, now: Long): Boolean = false

        override fun done() {}
    }
}

/**
 * The engine's `secure` store under the desktop's opt-in rule (the old app's `tokensMayPersist`), with
 * the session wrapped by this computer's key store at rest.
 *
 * - The session's tokens and keys are written to disk only while [keep] says the person opted in. Otherwise they live
 *   in this object for the run, and a restart lands on the first screen. A file left on disk while the opt-in is off
 *   (a crash between the switch and the delete) is deleted at the first read, unread. While the switch is
 *   [Keep.UNKNOWN] (its settings file could not be read) the file on disk is neither read nor deleted, and nothing is
 *   written to it: the run is held in memory until the person answers.
 * - Kept, the file is wrapped by [store] ([SessionWrap]) and stays owner-only. Where the store is missing or refuses,
 *   nothing falls back silently: the session is written unwrapped only once the person chose a file only their
 *   account can read ([plainChosen]); until then it is held in memory and [choiceNeeded] says the person must be asked.
 * - A session kept unwrapped is read only when the person chose that ([plainChosen]) or as an earlier build's file,
 *   once ([migration]); it is wrapped at the first read that can, once it has been read. Any other
 *   unwrapped file is [KeptForm.UNOPENABLE]: not read as a session, not deleted.
 * - A wrapped file that cannot be opened is [KeptForm.UNOPENABLE].
 */
class SignInStoreFile(
    private val file: File,
    private val store: OsKeyStore,
    private val log: (String) -> Unit = {},
    private val plainChosen: () -> Boolean = { false },
    private val migration: PlainMigration = PlainMigration.None,
    private val now: () -> Long = System::currentTimeMillis,
    private val pause: () -> Unit = { Thread.sleep(ASK_AGAIN_MS) },
    private val bindings: BindingRecord = BindingRecord.None,
    private val keep: () -> Keep,
) : DeviceStateFile {
    /** The unwrapped file on disk was accepted as the earlier build's migration and is not yet wrapped or answered. */
    private var migrating = false

    /**
     * The file is [KeptForm.UNOPENABLE] because the key store did not answer (a locked keyring
     * whose prompt was dismissed, a start before the keyring is up), not because of the file. Such a refusal may pass:
     * the file is never set aside for it; each later write asks again.
     */
    private var mayPass = false
    private val disk = OwnerOnlyFile(file)
    private var held: String? = null
    private var loaded = false

    /** The key this run seals with and its handle in [store], once one is known (read from the file, or made). */
    private var key: ByteArray? = null
    private var handle: ByteArray? = null

    /** A write found no key store and the person has not chosen a plain file: the session is held in memory only. */
    private var heldForChoice = false

    /** What the file holds, as this run knows it. */
    @Volatile
    var form: KeptForm = KeptForm.NONE
        private set

    @Synchronized
    override fun read(): String? {
        if (!loaded) {
            when (keep()) {
                Keep.ON -> held = load()
                Keep.OFF -> deleteFile()
                Keep.UNKNOWN -> {}
            }
            loaded = true
        }
        return held
    }

    private fun load(): String? {
        val text = disk.read() ?: return null.also { form = KeptForm.NONE }
        if (!SessionWrap.isWrapped(text)) {
            val chosen = plainChosen()
            if (!chosen && !migration.accept(text, now())) {
                form = KeptForm.UNOPENABLE
                mayPass = false
                log("kept session: an unwrapped file that this computer neither chose nor migrated was not read; it is left as it is")
                return null
            }
            if (!chosen) {
                migrating = true
                log("kept session: an earlier build's unwrapped file was accepted as its migration")
            }
            form = KeptForm.PLAIN
            // Read: now wrap it, where this computer can.
            if (seal(text)) log("kept session: an unwrapped file was wrapped by ${store.kind.id}")
            return text
        }
        val opened = try {
            openAsking(text)
        } catch (e: KeyStoreUnavailable) {
            form = KeptForm.UNOPENABLE
            mayPass = true
            log("kept session: the key store did not answer after $ASKS asks (${printable(e.message)}); the wrapped file is left as it is")
            return null
        } catch (e: Exception) {
            form = KeptForm.UNOPENABLE
            mayPass = false
            log("kept session: the wrapped file could not be opened (${printable(e.message)}); it is left as it is")
            return null
        }
        adopt(opened)
        // Sealed the old way (the account and server not bound): sealed again at once, with its own key.
        if (opened.oldSeal && seal(opened.plain)) log("kept session: a file sealed the old way was sealed again for its account and server")
        return opened.plain
    }

    /** Opens a wrapped file, asking the key store again (after a pause) while it does not answer: [ASKS] asks in all. */
    private fun openAsking(text: String): SessionWrap.Opened {
        var refused: KeyStoreUnavailable? = null
        repeat(ASKS) { i ->
            if (i > 0) pause()
            try {
                return SessionWrap.open(text, store, bindings.expected())
            } catch (e: KeyStoreUnavailable) {
                refused = e
            }
        }
        throw refused!!
    }

    private fun adopt(opened: SessionWrap.Opened) {
        key?.fill(0)
        key = opened.key
        handle = opened.handle
        form = KeptForm.WRAPPED
        mayPass = false
    }

    /**
     * The kept file did not open because the key store did not answer: ask again before anything is written. True when
     * the write may go on: the file opened now (its key is reused), it is gone, or the refusal is final (the store answers
     * a new key but still cannot give the file's back; that new key is then the one sealed with). False while the store
     * still does not answer: the file is left as it is and the session stays in memory.
     */
    private fun askAgain(): Boolean {
        // A key made while the file was unopenable (the switch's own check) was never written with: its item goes.
        handle?.let { store.forget(it) }
        key?.fill(0)
        key = null
        handle = null
        val text = try {
            disk.read()
        } catch (e: java.io.IOException) {
            return false
        } ?: return true.also { form = KeptForm.NONE; mayPass = false }
        try {
            adopt(openAsking(text))
            return true
        } catch (e: KeyStoreUnavailable) {
            // Still refused: below, whether the store answers at all.
        } catch (e: Exception) {
            mayPass = false
            return true
        }
        val fresh = SessionWrap.newKey()
        val h = try {
            store.keep(fresh)
        } catch (e: KeyStoreUnavailable) {
            fresh.fill(0)
            return false
        }
        // It answers now; a keep may have unlocked it, so the file's key is asked for once more.
        try {
            val opened = SessionWrap.open(text, store, bindings.expected())
            store.forget(h)
            fresh.fill(0)
            adopt(opened)
            return true
        } catch (e: Exception) {
            key?.fill(0)
            key = fresh
            handle = h
            mayPass = false
            log("kept session: the key store answers but cannot give back the kept file's key; that refusal is final")
            return true
        }
    }

    @Synchronized
    override fun replace(text: String) {
        held = text
        loaded = true
        if (keep() == Keep.ON) write(text)
    }

    private fun write(text: String) {
        if (form == KeptForm.UNOPENABLE && mayPass && !askAgain()) {
            log("kept session: the key store still does not answer; the session is held in memory and the kept file is left as it is")
            return
        }
        if (form == KeptForm.UNOPENABLE) {
            // Never deleted unread: kept aside under a new name before anything is written in its place.
            if (!disk.setAside()) {
                log("kept session: the file that could not be opened could not be moved aside; nothing written over it")
                // Nothing was sealed with a key made for this write: its item goes.
                handle?.let { store.forget(it) }
                key?.fill(0)
                key = null
                handle = null
                return
            }
            form = KeptForm.NONE
        }
        if (seal(text)) return
        if (plainChosen()) {
            disk.replace(text)
            wroteThisRun = true
            form = KeptForm.PLAIN
            heldForChoice = false
            migrationDone()
            return
        }
        heldForChoice = true
    }

    /** This run wrote the file now on disk (it is not the one the start found). */
    private var wroteThisRun = false

    /**
     * What was last written here is held in memory only: the key store gave no key and no unwrapped file was chosen, so
     * it does not outlive the run. Read only; nothing is asked of the key store.
     */
    @get:Synchronized
    val heldInMemoryOnly: Boolean
        get() = heldForChoice

    /**
     * Whether what the engine keeps here names a session ([SessionKeeper.KEY]). A sign-out, a forget of the session's
     * server and a deletion remove it; an act that ends elsewhere (another server forgotten) leaves it.
     */
    @get:Synchronized
    val holdsSession: Boolean
        get() = held?.let { SessionWrap.namesASession(it) } ?: false

    /**
     * The account open is not the one the switch belongs to: a file this run wrote for it is
     * removed with its key-store item. The file the start found, and every file set aside, stay as they are.
     */
    @Synchronized
    fun withdrawWrittenThisRun() {
        // A write held for the no-key-store question was that account's: nobody is asked about it once the switch's own
        // account is back (seen in the run: the question showed on the first screen after the other one signed out).
        heldForChoice = false
        if (!wroteThisRun || (form != KeptForm.WRAPPED && form != KeptForm.PLAIN)) return
        disk.delete()
        handle?.let { store.forget(it) }
        key?.fill(0)
        key = null
        handle = null
        form = KeptForm.NONE
        wroteThisRun = false
        log("kept session: a session written for an account the switch does not belong to was removed")
    }

    /** Writes [text] wrapped; false (nothing written) when the key store gave no key. */
    private fun seal(text: String): Boolean {
        val k = key ?: newKey() ?: return false
        disk.replace(SessionWrap.seal(text, k, store.kind, handle!!))
        wroteThisRun = true
        bindings.record(SessionWrap.bindingOf(text))
        form = KeptForm.WRAPPED
        heldForChoice = false
        migrationDone()
        return true
    }

    private fun migrationDone() {
        if (!migrating) return
        migrating = false
        migration.done()
    }

    private fun newKey(): ByteArray? {
        val k = SessionWrap.newKey()
        return try {
            handle = store.keep(k)
            key = k
            k
        } catch (e: KeyStoreUnavailable) {
            k.fill(0)
            log("kept session: no key store (${printable(e.message)})")
            null
        }
    }

    /**
     * Whether this computer's key store can keep the session now: a key is had (made and kept, when none was), so the
     * next write is wrapped. False is the question of "keep me signed in": a file only your account can read, or not.
     */
    @Synchronized
    fun keyStoreReady(): Boolean = key != null || newKey() != null

    /**
     * The person must be asked: the sign-in is kept, this computer's key store gave no key, and the person has not
     * chosen a file only their account can read. Either a write is held in memory, or an unwrapped file from before
     * is on disk.
     */
    @get:Synchronized
    val choiceNeeded: Boolean
        get() = keep() == Keep.ON && !plainChosen() && (heldForChoice || form == KeptForm.PLAIN)

    /** Whether anything is on disk now (for tests and for Settings). */
    val onDisk: Boolean get() = file.exists()

    @Synchronized
    fun keepChanged(on: Boolean) {
        if (on) held?.let { write(it) } else deleteFile()
    }

    /** A start with the switch off: the file goes before anything could read it. */
    @Synchronized
    fun deleteUnread() {
        if (!loaded) deleteFile()
    }

    /**
     * The switch went off (the person unticked it, or a sign-out, "Forget this server" or a deletion ended the account
     * kept here), or a start found it off: the kept file goes with its key-store item, and so does every file set aside
     * as unopenable beside it, with theirs. A file read by no one this run (a start with the
     * switch off) has its item found from the handle it carries.
     */
    private fun deleteFile() {
        if (handle == null) forgetItemOf(file)
        disk.delete()
        handle?.let { store.forget(it) }
        key?.fill(0)
        key = null
        handle = null
        heldForChoice = false
        mayPass = false
        wroteThisRun = false
        form = KeptForm.NONE
        migrationDone()
        val dir = file.absoluteFile.parentFile
        for (aside in SafeDelete.entries(dir).filter { it.name.startsWith(file.name + ASIDE) }) {
            forgetItemOf(aside)
            if (!SafeDelete.entry(aside, dir)) log("kept session: a file set aside as unopenable could not be deleted")
        }
    }

    /** Forgets the key-store item a wrapped file of this store names, if it is one. Never throws. */
    private fun forgetItemOf(f: File) {
        if (!SafeDelete.isRealFile(f)) return
        val text = runCatching { f.readText() }.getOrNull() ?: return
        SessionWrap.handleOf(text, store.kind)?.let { runCatching { store.forget(it) } }
    }

    companion object {
        /** How many times the key store is asked before its refusal is taken. */
        const val ASKS = 3

        /** The pause between two asks. */
        const val ASK_AGAIN_MS = 250L

        /** What [OwnerOnlyFile.setAside] (and the start's damaged-file screen) adds to the name of a file it sets aside. */
        const val ASIDE = ".unreadable-"
    }
}
