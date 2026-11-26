package io.silencelen.andvari.desktop.trust

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.platform.win32.Crypt32Util
import com.sun.jna.ptr.PointerByReference
import java.util.Base64

/**
 * The operating system's key store for this account: what wraps the kept session in
 * `secure-state.json` ([SignInStoreFile]). The platform calls stay behind this one small interface, so the rules of the
 * wrap (what is kept, what happens when the store is missing or refuses) are tested on any computer with a fake.
 *
 * A store keeps a 32-byte key outside the file, so the file alone (a copied disk, a backup of the home folder, another
 * account on the computer) does not open. What it does not do:
 * - Any program running as the same user can ask the store for the key: on Windows any process of that user can
 *   unprotect the blob, and on a domain-joined computer so can whoever holds the domain's DPAPI backup key; on Linux any
 *   program on the user's session bus can read the item. The seal keeps the session confidential at rest; it does not
 *   stop a program of the same user from reading it or writing a wrapped file of its own.
 * - On Windows the key's blob is in the file itself and [forget] does nothing, so an older copy of the file (a backup, a
 *   shadow copy) still opens after a sign-out. On Linux [forget] removes the item, and older copies no longer open.
 *
 * The stores:
 * - [WindowsDataProtection]: Windows data protection (DPAPI, per user). The handle is DPAPI's own blob of the key.
 * - [SecretServiceKeyStore]: the Linux desktop's secret service (GNOME Keyring, KWallet's service) through libsecret.
 *   The key is an item in the default collection; the handle names the item.
 * - [NoKeyStore]: neither is there. Every call refuses.
 */
interface OsKeyStore {
    val kind: KeyStoreKind

    /**
     * Keeps [key] for this account and returns the handle the wrapped file carries to find it again.
     * Throws [KeyStoreUnavailable] when the store is missing, locked shut or refuses.
     */
    fun keep(key: ByteArray): ByteArray

    /** The key [keep] kept under [handle]. Throws [KeyStoreUnavailable] when it cannot be had back. */
    fun recall(handle: ByteArray): ByteArray

    /** Removes what [keep] stored outside the handle (the secret service's item). Best effort: never throws. */
    fun forget(handle: ByteArray) {}
}

/** Which store wrapped a file; its [id] is written into the file, so a file wrapped on one platform is not opened by another. */
enum class KeyStoreKind(val id: String) {
    WINDOWS_DPAPI("dpapi"),
    SECRET_SERVICE("secret-service"),
    NONE("none"),
}

/** The key store is missing, locked shut, or refused. Its message never carries a key. */
class KeyStoreUnavailable(message: String, cause: Throwable? = null) : Exception(message, cause)

/** No key store on this computer: a Linux session with no secret service, or a platform this app has none for. */
object NoKeyStore : OsKeyStore {
    override val kind: KeyStoreKind get() = KeyStoreKind.NONE

    override fun keep(key: ByteArray): ByteArray = throw KeyStoreUnavailable("this computer has no key store")

    override fun recall(handle: ByteArray): ByteArray = throw KeyStoreUnavailable("this computer has no key store")
}

object OsKeyStores {
    /**
     * The store of the computer this runs on. Loading it makes no call to the store yet: a missing secret service is
     * found at the first [OsKeyStore.keep] or [OsKeyStore.recall].
     */
    fun forThisComputer(os: String = System.getProperty("os.name").orEmpty()): OsKeyStore {
        val name = os.lowercase()
        return when {
            name.contains("win") -> WindowsDataProtection
            name.contains("linux") -> SecretServiceKeyStore.load() ?: NoKeyStore
            else -> NoKeyStore
        }
    }
}

/**
 * Windows data protection for the signed-in Windows user (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`),
 * with no prompt (`CRYPTPROTECT_UI_FORBIDDEN`) and this app's own entropy, so another program's blob is not taken.
 */
internal object WindowsDataProtection : OsKeyStore {
    private const val CRYPTPROTECT_UI_FORBIDDEN = 0x1
    private val ENTROPY = "andvari-desktop kept session".encodeToByteArray()

    override val kind: KeyStoreKind get() = KeyStoreKind.WINDOWS_DPAPI

    override fun keep(key: ByteArray): ByteArray = try {
        Crypt32Util.cryptProtectData(key, ENTROPY, CRYPTPROTECT_UI_FORBIDDEN, "andvari", null)
    } catch (t: Throwable) {
        throw KeyStoreUnavailable("Windows data protection refused: ${t.javaClass.simpleName}", t)
    }

    override fun recall(handle: ByteArray): ByteArray = try {
        Crypt32Util.cryptUnprotectData(handle, ENTROPY, CRYPTPROTECT_UI_FORBIDDEN, null)
    } catch (t: Throwable) {
        throw KeyStoreUnavailable("Windows data protection could not open the key: ${t.javaClass.simpleName}", t)
    }
}

/**
 * The secret service through libsecret (`secret_password_store_sync` and its siblings), under this app's own schema.
 * Each key is an item named by a random id (the handle); the key itself is stored as base64 text. A session with no
 * secret service (no D-Bus session, no keyring daemon) answers every call with an error, which is [KeyStoreUnavailable].
 */
internal class SecretServiceKeyStore private constructor(private val lib: LibSecret, private val glib: GLib?) : OsKeyStore {
    override val kind: KeyStoreKind get() = KeyStoreKind.SECRET_SERVICE

    @Suppress("FunctionName")
    internal interface LibSecret : Library {
        fun secret_password_store_sync(schema: SecretSchema, collection: String?, label: String, password: String, cancellable: Pointer?, error: PointerByReference, vararg attributes: Any?): Int

        fun secret_password_lookup_sync(schema: SecretSchema, cancellable: Pointer?, error: PointerByReference, vararg attributes: Any?): Pointer?

        fun secret_password_clear_sync(schema: SecretSchema, cancellable: Pointer?, error: PointerByReference, vararg attributes: Any?): Int

        fun secret_password_free(password: Pointer?)
    }

    @Suppress("FunctionName")
    internal interface GLib : Library {
        fun g_error_free(error: Pointer?)
    }

    /** `SecretSchemaAttribute`: a name and its type (0, a string). */
    @Structure.FieldOrder("name", "type")
    class SecretSchemaAttribute : Structure() {
        @JvmField var name: String? = null

        @JvmField var type: Int = 0
    }

    /** `SecretSchema`: a name, flags, 32 attribute slots (the unused ones zero), and libsecret's reserved fields. */
    @Structure.FieldOrder("name", "flags", "attributes", "reserved", "reserved1", "reserved2", "reserved3", "reserved4", "reserved5", "reserved6", "reserved7")
    class SecretSchema : Structure() {
        @JvmField var name: String? = SCHEMA

        @JvmField var flags: Int = 0

        @JvmField var attributes: Array<SecretSchemaAttribute> = Array(32) { SecretSchemaAttribute() }

        @JvmField var reserved: Int = 0

        @JvmField var reserved1: Pointer? = null

        @JvmField var reserved2: Pointer? = null

        @JvmField var reserved3: Pointer? = null

        @JvmField var reserved4: Pointer? = null

        @JvmField var reserved5: Pointer? = null

        @JvmField var reserved6: Pointer? = null

        @JvmField var reserved7: Pointer? = null

        init {
            attributes[0].name = ID_ATTRIBUTE
        }
    }

    /** Held for the life of the store: JNA keeps the native copies of its strings alive with it. */
    private val schema = SecretSchema()

    override fun keep(key: ByteArray): ByteArray {
        val id = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val handle = Base64.getUrlEncoder().withoutPadding().encodeToString(id)
        val err = PointerByReference()
        val text = Base64.getEncoder().encodeToString(key)
        val ok = synchronized(lib) { lib.secret_password_store_sync(schema, null, LABEL, text, null, err, ID_ATTRIBUTE, handle, null) }
        failed(err)?.let { throw KeyStoreUnavailable("the secret service refused: $it") }
        if (ok == 0) throw KeyStoreUnavailable("the secret service refused")
        return handle.encodeToByteArray()
    }

    override fun recall(handle: ByteArray): ByteArray {
        val err = PointerByReference()
        val p = synchronized(lib) { lib.secret_password_lookup_sync(schema, null, err, ID_ATTRIBUTE, handle.decodeToString(), null) }
        failed(err)?.let {
            lib.secret_password_free(p)
            throw KeyStoreUnavailable("the secret service could not be asked: $it")
        }
        if (p == null) throw KeyStoreUnavailable("the secret service holds no such key")
        return try {
            Base64.getDecoder().decode(p.getString(0, "US-ASCII"))
        } catch (e: IllegalArgumentException) {
            throw KeyStoreUnavailable("the secret service's item is not a key")
        } finally {
            lib.secret_password_free(p)
        }
    }

    override fun forget(handle: ByteArray) {
        runCatching {
            val err = PointerByReference()
            synchronized(lib) { lib.secret_password_clear_sync(schema, null, err, ID_ATTRIBUTE, handle.decodeToString(), null) }
            failed(err)
        }
    }

    /** The GError's message when the call set one (then freed), else null. */
    private fun failed(err: PointerByReference): String? {
        val e = err.value ?: return null
        // GError: { GQuark domain; gint code; gchar *message }: the message is at offset 8 on 32- and 64-bit alike.
        val message = runCatching { e.getPointer(8)?.getString(0, "UTF-8") }.getOrNull()?.take(200) ?: "an error"
        runCatching { glib?.g_error_free(e) }
        return message
    }

    companion object {
        private const val SCHEMA = "io.silencelen.andvari.desktop.KeptSession"
        private const val ID_ATTRIBUTE = "andvari-key"
        private const val LABEL = "andvari: the key of the sign-in kept on this computer"

        /** libsecret, or null where it is not installed (then there is no key store). */
        fun load(): SecretServiceKeyStore? = runCatching {
            val lib = Native.load("libsecret-1.so.0", LibSecret::class.java)
            val glib = runCatching { Native.load("libglib-2.0.so.0", GLib::class.java) }.getOrNull()
            SecretServiceKeyStore(lib, glib)
        }.getOrNull()
    }
}
