package io.silencelen.andvari.core.client.autofill

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Guards the browser cert-pin table format. The Chrome pin shipped truncated by one
 * base64 char for three releases (43 chars → never decodes → Chrome autofill dead),
 * silently, because a malformed pin just never matches the on-device digest. Any digest
 * that is not standard base64 of exactly 32 bytes can never equal a real SHA-256, so it
 * is a build-time bug — this asserts every pinned digest is well-formed.
 */
@OptIn(ExperimentalEncodingApi::class)
class BrowserCertPinsTest {
    @Test
    fun everyPinnedDigestDecodesTo32Bytes() {
        val digests = BrowserCertPins.TABLE.values.flatten().toSet()
        assertTrue(digests.isNotEmpty(), "expected at least one pinned digest")
        for (d in digests) {
            assertEquals(44, d.length, "pin '$d' is ${d.length} chars; a base64 SHA-256 is exactly 44")
            val bytes = Base64.Default.decode(d)
            assertEquals(32, bytes.size, "pin '$d' decodes to ${bytes.size} bytes, expected 32")
        }
    }

    @Test
    fun tableKeysAndPinsAreConsistent() {
        // Every package maps to a set (empty = fail-closed placeholder is allowed); no
        // package should map to a null/blank digest string.
        for ((pkg, pins) in BrowserCertPins.TABLE) {
            assertTrue(pkg.isNotBlank(), "blank package id in pin table")
            assertTrue(pins.all { it.isNotBlank() }, "blank digest under $pkg")
        }
    }
}
