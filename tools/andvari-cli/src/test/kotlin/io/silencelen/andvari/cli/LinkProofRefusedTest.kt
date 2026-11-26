package io.silencelen.andvari.cli

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The shared step's stop for a device link whose pickup the server refused for a password that opens this device's copy
 * of the account (`reauth_failed`): said as what is so, under the exit code and key of a proof the server refused, never as
 * a wrong password. The stop needs a copy of the account on the device to compare with; this tool keeps none between
 * runs (its session sink hands the shared step nothing to compare), so no run against a real server reaches it today, and
 * the words are held here.
 */
class LinkProofRefusedTest {
    @Test fun aRefusedProofOfAPasswordThatOpensThisDevicesCopyIsItsOwnStop() {
        val e = linkProofRefusedError("https://vault.example.org")
        assertEquals(EXIT_PROOF_REFUSED, e.code)
        assertEquals(KEY_PROOF_REFUSED, e.key)
        assertEquals(fill(LINK_PROOF_REFUSED, "https://vault.example.org"), e.message)
        assertTrue(e.message!!.contains("isn't a wrong password"))
        assertFalse(e.message!!.contains("wrong master password"))
    }
}
