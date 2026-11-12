package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The personal-vault banner when two vaults share a name (an iOS device showed "Your account's personal vault is
 * Personal, but the server sent Personal" for ONE vault): the same-vault case says so and offers no "Keep", a
 * different-vault case says they are two vaults, and every vault on offer carries the facts that tell it apart.
 */
class PersonalVaultNoticeCopyTest {
    private val source = listOf(File("src/main/kotlin/io/silencelen/andvari/app/HouseholdScreen.kt"), File("app-android/src/main/kotlin/io/silencelen/andvari/app/HouseholdScreen.kt"))
        .first { it.isFile }.readText()

    private fun branch(status: String): String = source.substringAfter("status == Account.PersonalStatus.$status) {").substringBefore("return\n    }")

    @Test
    fun theSameVaultIsOneVaultToConfirmNotAChoiceBetweenTwo() {
        val proposed = branch("PROPOSED")
        assertTrue(proposed.contains("val same = change.currentVaultId == change.servedVaultId"))
        assertTrue(proposed.contains("change.currentVaultId.takeIf { it.isNotEmpty() && !same }"), "no \"Keep\" of the very vault the server sent")
        assertTrue(proposed.contains("same -> PersonalVaultCopy.sameVaultTitle(newName)"))
        assertTrue(proposed.contains("same -> PersonalVaultCopy.sameVaultBody(change.servedVaultId)"))
        assertTrue(proposed.contains("\${PersonalVaultCopy.DIFFERENT_VAULTS} Another of your devices chose"), "two vaults are said to be two")
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
