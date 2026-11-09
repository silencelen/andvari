@file:OptIn(BetaInteropApi::class)

package io.silencelen.andvari.core.client.autofill

import kotlinx.cinterop.BetaInteropApi
import platform.Foundation.NSString
import platform.Foundation.create
import platform.Foundation.precomposedStringWithCanonicalMapping

/** NFC for [Idna]; the idna vectors pin it against the JVM's java.text.Normalizer. */
internal actual fun nfc(s: String): String = NSString.create(string = s).precomposedStringWithCanonicalMapping
