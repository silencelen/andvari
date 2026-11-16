package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
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

    private val other = "00000000-0000-4000-8000-000000123456"

    @Test
    fun aFirstSignInWhoseTwoRecordsNameOneVaultAsksToConfirmItAndOffersNothingToKeep() {
        // A new device's first sign-in: its proposal is described against the account's record once that is read, and the
        // record names the very vault the server sent.
        val n = PersonalVaultCopy.proposedNotice(id, id, currentName = "Personal", servedName = "Personal")
        assertEquals("Confirm your personal vault on this device: Personal.", n.title)
        assertEquals(PersonalVaultCopy.sameVaultBody(id) + " Until you confirm, new items need a vault picked by hand.", n.body)
        assertNull(n.keepName, "no \"Keep\" of the very vault the server sent")
        assertFalse((n.title + n.body).contains("but the server sent"), "nothing reads as a choice between two vaults")
        assertFalse(n.body.contains(PersonalVaultCopy.DIFFERENT_VAULTS))
    }

    @Test
    fun twoVaultsOfOneNameAreSaidToBeTwoAndTheAccountsIsTheOneToKeep() {
        val n = PersonalVaultCopy.proposedNotice(other, id, currentName = "Personal", servedName = "Personal")
        assertEquals("Your account's personal vault is Personal, but the server sent Personal.", n.title)
        assertEquals(
            "These are two different vaults. Another of your devices chose Personal, or the server sent an older record. This device uses no personal vault until you decide.",
            n.body,
        )
        assertEquals("Personal", n.keepName)
    }

    @Test
    fun noRecordLeavesTheServersWordAlone() {
        val n = PersonalVaultCopy.proposedNotice("", id, currentName = null, servedName = "Personal")
        assertEquals("The server says your personal vault is Personal.", n.title)
        assertEquals("This device hasn't confirmed it yet, so it uses no personal vault until you decide: new items need a vault picked by hand.", n.body)
        assertNull(n.keepName)
    }

    @Test
    fun factsTellTwoVaultsOfOneNameApart() {
        assertEquals("1 item · created 2026-11-01 · last changed 2026-11-11 · id ending abcdef", PersonalVaultCopy.facts(1, 1_793_491_200_000, 1_794_355_200_000, id))
        assertEquals("3 items · id ending abcdef", PersonalVaultCopy.facts(3, null, 0, id), "unknown dates are left out")
        assertEquals("0 items · id ending abcdef", PersonalVaultCopy.facts(0, 0, null, id))
    }
}
