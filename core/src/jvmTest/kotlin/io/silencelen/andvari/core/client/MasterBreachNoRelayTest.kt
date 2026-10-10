package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertFalse

/**
 * Security review 2026-10, root cause C: [Strength] used to carry `breachCount`, the seam every
 * native master-password / backup-passphrase breach check went through, and it handed the SHA-1
 * prefix to `AndvariApi.hibpRange` — the vault server that also holds the Argon2id verifier. The
 * seam and its "nothing left this device" sentence are gone, so no native surface can route a
 * master-password-derived value to the server through core. Item passwords still match ranges
 * through [io.silencelen.andvari.core.crypto.Hibp] directly (the Health scan).
 */
class MasterBreachNoRelayTest {
    @Test
    fun strengthHasNoBreachSeam() {
        val members = Strength::class.java.declaredMethods.map { it.name } + Strength::class.java.declaredFields.map { it.name }
        assertFalse(members.any { it.startsWith("breachCount") }, "Strength must not offer a master-password breach lookup")
        assertFalse(members.contains("BREACHED_PASSWORD_WARNING"), "the 'sent nothing' breach sentence must not ship")
    }
}
