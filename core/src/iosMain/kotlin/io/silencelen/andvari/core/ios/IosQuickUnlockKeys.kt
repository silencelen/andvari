@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.BiometricOutcome
import io.silencelen.andvari.core.client.session.LocalAuthenticationCodes
import io.silencelen.andvari.core.client.session.QuickEnroll
import io.silencelen.andvari.core.client.session.QuickRecover
import io.silencelen.andvari.core.client.session.QuickUnlockCopy
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryGetValue
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.NSMakeRange
import platform.Foundation.NSMutableData
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSNumber
import platform.Foundation.appendBytes
import platform.Foundation.numberWithInt
import platform.Foundation.resetBytesInRange
import platform.LocalAuthentication.LABiometryTypeTouchID
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
import platform.Security.SecAccessControlCreateWithFlags
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecKeyCopyAttributes
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateDecryptedData
import platform.Security.SecKeyCreateEncryptedData
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyRef
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAccessControlBiometryCurrentSet
import platform.Security.kSecAccessControlPrivateKeyUsage
import platform.Security.kSecAttrAccessControl
import platform.Security.kSecAttrAccessGroup
import platform.Security.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrTokenID
import platform.Security.kSecAttrTokenIDSecureEnclave
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecClassKey
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
import platform.Security.kSecPrivateKeyAttrs
import platform.Security.kSecReturnRef
import platform.Security.kSecUseAuthenticationContext
import kotlin.coroutines.resume

/**
 * iOS quick unlock (spec 01 §8.1, design 2026-11-09): the UVK, never the password, wrapped under a Secure Enclave
 * P-256 key created with `biometryCurrentSet` and `privateKeyUsage`, usable only while a passcode is set, on this
 * device only (`WhenPasscodeSetThisDeviceOnly`). Enrolling a new face or finger invalidates it. The wrap is ECIES
 * (cofactor X9.63, SHA-256, AES-GCM); its blob is kept in the Keychain, this device only.
 *
 * Encrypting needs no biometric, and spec 01 §8.1 requires one at enrollment, so a LocalAuthentication prompt is
 * evaluated first. Unlocking evaluates the prompt and hands its context to the key lookup, so the decryption needs no
 * second prompt. The outcomes follow Android's table ([LocalAuthenticationCodes], [QuickUnlockCopy]): a cancel, a
 * fallback and a lockout keep the enrollment; a changed biometric set, an invalidated key or a corrupt blob wipe it.
 */
internal class IosQuickUnlockKeys(private val blobs: KeychainSecrets, private val accessGroup: String?) : QuickUnlockKeys {
    private fun tag(originKey: String, userId: String) = "io.silencelen.andvari.quickunlock.$originKey.${OriginCanon.pathSafe(userId)}"

    private fun blobName(originKey: String, userId: String) = "quickunlock.$originKey.${OriginCanon.pathSafe(userId)}"

    private fun reasonOf(host: BiometricHost, fallback: String) = (host as? IosBiometricHost)?.reason?.takeIf { it.isNotBlank() } ?: fallback

    override fun hasStrongBiometric(): Boolean = biometricRefusal() == null

    override fun biometricProblem(): String? = biometricRefusal()?.let { (code, name) -> LocalAuthenticationCodes.unavailable(code, name) }

    /**
     * Null when a fresh context can evaluate the biometric policy; otherwise its error code (null when it gave none) and the
     * name of the biometric the device has. The code is what tells a person who has not set one up from an app that was
     * refused it in Settings.
     */
    private fun biometricRefusal(): Pair<Long?, String>? = runCatching {
        memScoped {
            val context = LAContext()
            val error = alloc<ObjCObjectVar<NSError?>>()
            if (context.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, error.ptr)) {
                null
            } else {
                Pair(error.value?.code, if (context.biometryType == LABiometryTypeTouchID) "Touch ID" else "Face ID")
            }
        }
    }.getOrElse { Pair(null, "Face ID") }

    override fun isEnrolled(originKey: String, userId: String): Boolean = blobs.read(blobName(originKey, userId)) != null

    override suspend fun enroll(host: BiometricHost, originKey: String, userId: String, account: Account): QuickEnroll {
        val context = LAContext()
        evaluate(context, reasonOf(host, "Turn on quick unlock"))?.let { return QuickUnlockCopy.enrollFailure(it) }
        wipe(originKey, userId) // a new enrollment replaces any earlier one
        // The second key exists only in a simulator build ([simulatorQuickUnlockKey]); on a device it is always null.
        val key = createKey(tag(originKey, userId)) ?: simulatorQuickUnlockKey(tag(originKey, userId), accessGroup)
            ?: return QuickEnroll.Failed(QuickUnlockCopy.NO_SECURE_HARDWARE)
        if (!acceptable(key)) {
            CFRelease(key)
            wipe(originKey, userId)
            return QuickEnroll.Failed(QuickUnlockCopy.NO_SECURE_HARDWARE)
        }
        try {
            val publicKey = SecKeyCopyPublicKey(key) ?: return failEnroll(originKey, userId)
            val wrapped = try {
                // A copy leaves the account only here; it is zeroed whatever happens. A vault that locked under the
                // prompt has nothing to wrap.
                val uvk = try {
                    account.uvkCopyForPlatformWrap()
                } catch (e: AccountWipedException) {
                    return failEnroll(originKey, userId)
                }
                try {
                    encrypt(publicKey, uvk)
                } finally {
                    uvk.fill(0)
                }
            } finally {
                CFRelease(publicKey)
            }
            if (wrapped == null || !blobs.write(blobName(originKey, userId), Bytes.toB64(wrapped))) return failEnroll(originKey, userId)
            return QuickEnroll.Ok
        } finally {
            CFRelease(key)
        }
    }

    override suspend fun recover(host: BiometricHost, originKey: String, userId: String): QuickRecover {
        val blob = blobs.read(blobName(originKey, userId))
        val wrapped = blob?.let { runCatching { Bytes.fromB64(it) }.getOrNull() }
        if (wrapped == null || wrapped.isEmpty()) {
            wipe(originKey, userId)
            return QuickRecover.Wiped(QuickUnlockCopy.SET_UP_AGAIN)
        }
        val context = LAContext()
        context.localizedFallbackTitle = "Use master password"
        evaluate(context, reasonOf(host, "Unlock andvari"))?.let { outcome ->
            val r = QuickUnlockCopy.recoverFailure(outcome)
            if (r is QuickRecover.Wiped) wipe(originKey, userId)
            return r
        }
        return memScoped {
            val owned = CfOwned()
            try {
                val query = owned.dictionary(
                    kSecClass to kSecClassKey,
                    kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrApplicationTag to owned.retain(tag(originKey, userId).encodeToByteArray().toNSData()),
                    kSecReturnRef to kCFBooleanTrue,
                    kSecUseAuthenticationContext to owned.retain(context),
                    *owned.group(accessGroup),
                )
                val out = alloc<CFTypeRefVar>()
                val status = SecItemCopyMatching(query, out.ptr)
                if (status == errSecItemNotFound) {
                    // The system removed the key: the biometric set or the passcode changed.
                    wipe(originKey, userId)
                    return@memScoped QuickRecover.Wiped(QuickUnlockCopy.BIOMETRICS_CHANGED)
                }
                val key: SecKeyRef = out.value?.reinterpret() ?: return@memScoped QuickRecover.Fallback(QuickUnlockCopy.DEVICE_FALLBACK)
                if (status != errSecSuccess) {
                    CFRelease(key)
                    return@memScoped QuickRecover.Fallback(QuickUnlockCopy.DEVICE_FALLBACK)
                }
                if (!acceptable(key)) {
                    // Outside the simulator a key that is not the Secure Enclave's is never used (round-8 review L).
                    CFRelease(key)
                    wipe(originKey, userId)
                    return@memScoped QuickRecover.Wiped(QuickUnlockCopy.SET_UP_AGAIN)
                }
                try {
                    val error = alloc<CFErrorRefVar>()
                    val cipher: CFDataRef? = owned.retain(wrapped.toNSData())?.reinterpret()
                    val plain = SecKeyCreateDecryptedData(key, kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM, cipher, error.ptr)
                    if (plain == null) {
                        val code = error.value?.let { e -> CFErrorGetCode(e).also { CFRelease(e) } }
                        if (code == USER_CANCELED) return@memScoped QuickRecover.Fallback(null)
                        // A tampered or corrupt blob, or a key that no longer works: set it up again.
                        wipe(originKey, userId)
                        return@memScoped QuickRecover.Wiped(QuickUnlockCopy.SET_UP_AGAIN)
                    }
                    val data = CFBridgingRelease(plain) as NSData
                    val uvk = data.toByteArray()
                    if (uvk.size != 32) {
                        uvk.fill(0)
                        wipe(originKey, userId)
                        return@memScoped QuickRecover.Wiped(QuickUnlockCopy.SET_UP_AGAIN)
                    }
                    QuickRecover.Ok(uvk)
                } finally {
                    CFRelease(key)
                }
            } finally {
                owned.release()
            }
        }
    }

    override fun wipe(originKey: String, userId: String) {
        runCatching { blobs.write(blobName(originKey, userId), null) }
        runCatching {
            val owned = CfOwned()
            try {
                val query = owned.dictionary(
                    kSecClass to kSecClassKey,
                    kSecAttrApplicationTag to owned.retain(tag(originKey, userId).encodeToByteArray().toNSData()),
                    *owned.group(accessGroup),
                )
                SecItemDelete(query)
            } finally {
                owned.release()
            }
        }
    }

    /**
     * Every quick-unlock blob and key this app holds, whoever's (round-8 review L): what an install must not inherit from
     * the one before it, since the Keychain outlives an uninstall. The access group holds nothing else.
     */
    fun wipeAll() {
        runCatching { blobs.deleteAll() }
        runCatching {
            val owned = CfOwned()
            try {
                SecItemDelete(owned.dictionary(kSecClass to kSecClassKey, kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom, *owned.group(accessGroup)))
            } finally {
                owned.release()
            }
        }
    }

    /**
     * Whether [key] may wrap or unwrap the vault key: on a device only a key in the Secure Enclave (round-8 review L), so a
     * software key, the simulator's stand-in or any other, is refused at run time whatever was built in.
     */
    private fun acceptable(key: SecKeyRef): Boolean = inSimulator() || inSecureEnclave(key)

    private fun inSecureEnclave(key: SecKeyRef): Boolean {
        val attributes = SecKeyCopyAttributes(key) ?: return false
        return try {
            val token = CFDictionaryGetValue(attributes, kSecAttrTokenID) ?: return false
            val name = CFBridgingRelease(CFRetain(token)) as? String
            name != null && name == CFBridgingRelease(CFRetain(kSecAttrTokenIDSecureEnclave)) as? String
        } finally {
            CFRelease(attributes)
        }
    }

    private fun failEnroll(originKey: String, userId: String): QuickEnroll {
        wipe(originKey, userId)
        return QuickEnroll.Failed(null)
    }

    /** The LocalAuthentication prompt: null when it released, otherwise what its failure means. */
    private suspend fun evaluate(context: LAContext, reason: String): BiometricOutcome? =
        suspendCancellableCoroutine { cont ->
            context.evaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, localizedReason = reason) { ok, error ->
                cont.resume(if (ok) null else LocalAuthenticationCodes.outcome(error?.code ?: -1L))
            }
            cont.invokeOnCancellation { context.invalidate() }
        }

    /** A Secure Enclave P-256 key, bound to the current biometric set and a set passcode, or null where there is none. */
    private fun createKey(tag: String): SecKeyRef? = memScoped {
        val owned = CfOwned()
        val error = alloc<CFErrorRefVar>()
        try {
            val access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                kSecAccessControlPrivateKeyUsage or kSecAccessControlBiometryCurrentSet,
                error.ptr,
            ) ?: return@memScoped null
            val privateAttrs = owned.dictionary(
                kSecAttrIsPermanent to kCFBooleanTrue,
                kSecAttrApplicationTag to owned.retain(tag.encodeToByteArray().toNSData()),
                kSecAttrAccessControl to access,
                *owned.group(accessGroup),
            )
            CFRelease(access) // the dictionary holds it now
            val attrs = owned.dictionary(
                kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits to owned.retain(NSNumber.numberWithInt(256)),
                kSecAttrTokenID to kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs to privateAttrs,
            )
            SecKeyCreateRandomKey(attrs, error.ptr)
        } finally {
            error.value?.let { CFRelease(it) }
            owned.release()
        }
    }

    /** ECIES-wrap [plain] under [publicKey]; the plaintext buffer handed to the framework is zeroed afterwards. */
    private fun encrypt(publicKey: SecKeyRef, plain: ByteArray): ByteArray? = memScoped {
        val owned = CfOwned()
        val error = alloc<CFErrorRefVar>()
        // A mutable buffer, so the plaintext copy the framework reads can be zeroed afterwards.
        val buffer = NSMutableData()
        plain.usePinned { buffer.appendBytes(it.addressOf(0), plain.size.convert()) }
        try {
            val data: CFDataRef? = owned.retain(buffer)?.reinterpret()
            val wrapped = SecKeyCreateEncryptedData(publicKey, kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM, data, error.ptr)
                ?: return@memScoped null
            (CFBridgingRelease(wrapped) as NSData).toByteArray()
        } finally {
            buffer.resetBytesInRange(NSMakeRange(0u, buffer.length))
            error.value?.let { CFRelease(it) }
            owned.release()
        }
    }

    private companion object {
        /** errSecUserCanceled. */
        const val USER_CANCELED = -128L
    }
}

/**
 * The stand-in key of a simulator build, where there is no Secure Enclave, so the UI tests can exercise quick unlock.
 * Always null on a device: the device actual is one line, and the simulator's code is not compiled into it. A key that
 * is not the Secure Enclave's is refused on a device at run time as well ([IosQuickUnlockKeys]).
 */
internal expect fun simulatorQuickUnlockKey(tag: String, accessGroup: String?): SecKeyRef?

/** Whether this process runs in the iOS Simulator: its environment says so, which a device's never does. */
internal fun inSimulator(): Boolean {
    val env = NSProcessInfo.processInfo.environment
    return env["SIMULATOR_DEVICE_NAME"] != null || env["SIMULATOR_UDID"] != null
}

/**
 * A class every build of the framework declares in its generated header. The CI check that the device framework holds
 * no simulator key looks for it first, so a pass means it could read the header (.github/workflows/ios-core.yml).
 * Nothing uses it.
 */
class QuickUnlockSecureEnclaveOnly
