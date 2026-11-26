package io.silencelen.andvari.app.trust

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Enrolment's second step on Android. The prompt authorised one cipher; [AndroidKeyWrap.Sealer]
 * seals the guard's own lent buffer with it once, at once, never zeroing or keeping it, and answers null when it cannot
 * (used, discarded, or a cipher whose operation the Keystore dropped). A software AES key stands in for the Keystore's.
 */
class AndroidKeyWrapSealTest {
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val aad = "andvari/ovh|quick|test".encodeToByteArray()

    private fun authorised(): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }

    @Test fun itSealsOnceWithoutTouchingTheLentBufferAndTheSealOpens() {
        val lent = ByteArray(32) { (it + 1).toByte() }
        val before = lent.copyOf()
        val sealer = AndroidKeyWrap.Sealer(authorised(), aad.copyOf())
        val sealed = assertNotNull(sealer.seal(lent))
        assertContentEquals(before, lent, "the guard's buffer is neither zeroed nor changed")
        assertNull(sealer.seal(lent), "single use")
        val (iv, ct) = assertNotNull(AndroidKeyWrap.parse(sealed))
        val open = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)); updateAAD(aad) }
        assertContentEquals(before, open.doFinal(ct), "the sealed form opens to the secret under the same associated data")
    }

    @Test fun aDiscardedOrDroppedPreparationSealsNothing() {
        val lent = ByteArray(32) { 5 }
        val discarded = AndroidKeyWrap.Sealer(authorised(), aad.copyOf())
        discarded.discard()
        assertNull(discarded.seal(lent))
        // A cipher whose operation is gone (here, never initialised): doFinal throws, and nothing is sealed.
        assertNull(AndroidKeyWrap.Sealer(Cipher.getInstance("AES/GCM/NoPadding"), aad.copyOf()).seal(lent))
        assertContentEquals(ByteArray(32) { 5 }, lent)
    }
}
