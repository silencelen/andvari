package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.PersonalVaultCopy
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The personal-vault banner when two vaults share a name (the Android app's PersonalVaultNoticeCopyTest, for this app):
 * a first sign-in whose account record and served record name the SAME vault asks to confirm that one vault and offers
 * no "Keep" (it read "Your account's personal vault is Personal, but the server sent Personal"); a different-vault case
 * says they are two vaults; and every vault on offer carries the facts that tell it apart (core PersonalVaultCopy).
 */
class PersonalVaultNoticeCopyTest {
    private val source = listOf(File("src/main/kotlin/io/silencelen/andvari/desktop/Household.kt"), File("app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Household.kt"))
        .first { it.isFile }.readText()

    private fun branch(status: String): String = source.substringAfter("status == Account.PersonalStatus.$status) {").substringBefore("return\n    }")

    @Test
    fun theSameVaultIsOneVaultToConfirmAndTwoVaultsAreSaidToBeTwo() {
        val id = "00000000-0000-4000-8000-00000000abcdef"
        val other = "00000000-0000-4000-8000-000000123456"
        // The same id twice (a first sign-in once the account state has been read): one vault to confirm, nothing to keep.
        val same = PersonalVaultCopy.proposedNotice(id, id, currentName = "Personal", servedName = "Personal")
        assertEquals("Confirm your personal vault on this device: Personal.", same.title)
        assertNull(same.keepName)
        assertFalse((same.title + same.body).contains("but the server sent"))
        // Two ids of one name: said to be two vaults, and the account's is the one "Keep" keeps.
        val two = PersonalVaultCopy.proposedNotice(other, id, currentName = "Personal", servedName = "Personal")
        assertEquals("Your account's personal vault is Personal, but the server sent Personal.", two.title)
        assertTrue(two.body.startsWith(PersonalVaultCopy.DIFFERENT_VAULTS))
        assertEquals("Personal", two.keepName)
    }

    @Test
    fun theBannerSaysWhatCoreSaysAndKeepsOnlyAnotherVault() {
        val proposed = branch("PROPOSED")
        assertTrue(proposed.contains("val notice = PersonalVaultCopy.proposedNotice(\n            change.currentVaultId,\n            change.servedVaultId,"))
        assertTrue(proposed.contains("Text(notice.title, "))
        assertTrue(proposed.contains("Text(notice.body, "))
        assertTrue(proposed.contains("val designated = notice.keepName"), "\"Keep\" only for another vault than the one the server sent")
        assertFalse(proposed.contains("but the server sent"), "no words of its own for the two records")
        assertTrue(branch("CHANGED").contains("\${PersonalVaultCopy.DIFFERENT_VAULTS} Another of your devices changed it"))
    }

    @Test
    fun everyVaultOnOfferCarriesItsFacts() {
        val proposed = branch("PROPOSED")
        assertTrue(proposed.contains("The vault your account's record points to: \${vm.vaultFacts(change.currentVaultId)}."))
        assertTrue(proposed.contains("The vault the server sent: \${vm.vaultFacts(change.servedVaultId)}."))
        val changed = branch("CHANGED")
        assertTrue(changed.contains("The vault this device uses now: \${vm.vaultFacts(change.currentVaultId)}."))
        assertTrue(changed.contains("The vault the server sent: \${vm.vaultFacts(change.servedVaultId)}."))
        assertTrue(source.contains("id ending \${PersonalVaultCopy.idTail(c.vaultId)}"), "a first choice names each vault by the end of its id")
        assertTrue(source.contains("Text(vm.vaultFacts(c.vaultId)"))
        assertTrue(source.contains("Text(vm.vaultFacts(v.vaultId)"), "and so does the Settings re-designation")
    }
}
