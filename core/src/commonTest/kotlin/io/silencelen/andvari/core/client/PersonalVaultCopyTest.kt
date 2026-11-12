package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PersonalVaultCopyTest {
    private val id = "00000000-0000-4000-8000-00000000abcdef"

    @Test
    fun theSameVaultIsNamedAsOneVaultWithItsIdTail() {
        assertEquals("Confirm your personal vault on this device: Personal.", PersonalVaultCopy.sameVaultTitle("Personal"))
        val body = PersonalVaultCopy.sameVaultBody(id)
        assertTrue(body.contains("name the same vault (id ending abcdef)"), body)
        assertFalse(body.contains("but the server sent"), "nothing reads as a choice between two vaults")
    }

    @Test
    fun factsTellTwoVaultsOfOneNameApart() {
        assertEquals("1 item · created 2026-11-01 · last changed 2026-11-11 · id ending abcdef", PersonalVaultCopy.facts(1, 1_793_491_200_000, 1_794_355_200_000, id))
        assertEquals("3 items · id ending abcdef", PersonalVaultCopy.facts(3, null, 0, id), "unknown dates are left out")
        assertEquals("0 items · id ending abcdef", PersonalVaultCopy.facts(0, 0, null, id))
    }
}
