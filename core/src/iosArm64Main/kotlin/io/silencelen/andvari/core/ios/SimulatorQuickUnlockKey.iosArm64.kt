@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.ios

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Security.SecKeyRef

/** A device has a Secure Enclave or it has no quick unlock: there is no other key. */
internal actual fun simulatorQuickUnlockKey(tag: String, accessGroup: String?): SecKeyRef? = null
