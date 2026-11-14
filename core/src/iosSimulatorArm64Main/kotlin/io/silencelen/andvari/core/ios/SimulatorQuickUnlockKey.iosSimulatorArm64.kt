@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.ios

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.NSLog
import platform.Foundation.NSNumber
import platform.Foundation.numberWithInt
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyRef
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecPrivateKeyAttrs

/**
 * SIMULATOR ONLY. The iOS Simulator has no Secure Enclave, so the real key cannot be made there and quick unlock
 * could never be exercised by a test. This is an ordinary software P-256 key in the simulator's Keychain, under the
 * same tag and access group, so that everything around the key (the Face ID prompt, the wrapped blob, the gates, the
 * extensions reading it) runs as on a phone. It has none of the real key's protection: no hardware, no passcode
 * requirement, and enrolling another face does not invalidate it.
 *
 * This file is in the `iosSimulatorArm64Main` source set, which is compiled only for the simulator target. The device
 * target (`iosArm64Main`) has a one-line actual that returns null. .github/workflows/ios-core.yml checks that the
 * class below ([SimulatorSoftwareQuickUnlockKey]) is absent from the device framework the app links, and a device
 * refuses any key that is not the Secure Enclave's at run time anyway.
 */
internal actual fun simulatorQuickUnlockKey(tag: String, accessGroup: String?): SecKeyRef? = memScoped {
    val owned = CfOwned()
    val error = alloc<CFErrorRefVar>()
    try {
        val privateAttrs = owned.dictionary(
            kSecAttrIsPermanent to kCFBooleanTrue,
            kSecAttrApplicationTag to owned.retain(tag.encodeToByteArray().toNSData()),
            kSecAttrAccessible to kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            *owned.group(accessGroup),
        )
        val attrs = owned.dictionary(
            kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits to owned.retain(NSNumber.numberWithInt(256)),
            kSecPrivateKeyAttrs to privateAttrs,
        )
        val key = SecKeyCreateRandomKey(attrs, error.ptr)
        val code = error.value?.let { CFErrorGetCode(it) }
        NSLog("andvari: simulator-only software quick-unlock key, never built for a device; created=" + (key != null) + " error=" + code)
        key
    } finally {
        error.value?.let { CFRelease(it) }
        owned.release()
    }
}

/**
 * The class that marks a framework built with the simulator's software key, never a device's: the CI looks for it in
 * the framework's generated header. Nothing uses it.
 */
class SimulatorSoftwareQuickUnlockKey
