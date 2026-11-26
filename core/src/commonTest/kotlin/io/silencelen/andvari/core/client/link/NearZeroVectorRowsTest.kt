package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.DeviceLink
import io.silencelen.andvari.core.trust.Links
import io.silencelen.andvari.core.trust.VaultLog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The near-zero rows that took the place of the three vector rows whose inputs were all-zero keys (`links.json`
 * derive[2], `devicelink.json` derive[2], `vaultlog.json` vkCommit.derive[3]): the lowest input, 31 zero bytes and one
 * 0x01, since the key floor (spec 01 "Keys in memory and the lock", rule 4) refuses all zeros. The independent oracle
 * (`tools/vector-gen/oracle`) computed the values in the files by itself; they equal the constants here, which the
 * Kotlin implementation computed first. The vector tests now grade those rows as ordinary rows; this test keeps the constants
 * and, in [allZerosStaysRefused], the floor itself tested without any file (`keyfloor.json` is the file's form of it).
 */
class NearZeroVectorRowsTest {
    private val crypto = createCryptoProvider()
    private val nearZero = ByteArray(32).also { it[31] = 1 }

    @Test fun theSharedCodeDerivesTheReplacementRows() {
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE", Bytes.toB64(nearZero))

        val link = Links.deriveKeys(crypto, nearZero)
        assertEquals("hzkUh6ecy7WRa1h-5HlyAQ", link.linkId)
        assertEquals("tXu4oOoyVykFOY7K0stodAHcUowFmW74-kNkacv-YYk", Bytes.toB64(link.offerKey))
        assertEquals("NhgY05_LiuI2byGjAmuApP6iln14G-upUaHFcgLR6g8", Bytes.toB64(link.answerKey))
        assertEquals("D_VXZf9nn5tyJmQWSOV0yqvGWNeVBQRltWW-s6FpgEM", link.registerToken)
        assertEquals("ipBb99Eadt6XuYR77kcqElPMFRpKwp0mK8zXNJvxzQw", Links.tokenHash(crypto, link.registerToken))

        val dl = DeviceLink.deriveKeys(crypto, nearZero)
        assertEquals("pdiCh7MrlFmKw84sWupyRA", dl.linkId)
        assertEquals("ltzxYRSlua9Xxk4bzIW8-J2dgC51mkXcFKQCSOW_EVI", Bytes.toB64(dl.macKey))

        assertEquals("431cb0e19988a245876d7e9bd251dcf105399d05b537d667b3d5fd9c65c024de", VaultLog.vkCommit(crypto, nearZero, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
    }

    @Test fun allZerosStaysRefused() {
        val zero = ByteArray(32)
        assertFailsWith<KeysGoneException> { Links.deriveKeys(crypto, zero) }
        assertFailsWith<KeysGoneException> { DeviceLink.deriveKeys(crypto, zero) }
        assertFailsWith<KeysGoneException> { VaultLog.vkCommit(crypto, zero, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") }
    }
}
