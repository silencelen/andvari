package io.silencelen.andvari.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Delete account on the desktop (spec 03 §13): the steps are core's AccountDeletionFlow (tested in core, with the iOS
 * controller running them against a server stand-in); these pin the desktop's wiring around them. Settings offers it;
 * once the server deleted the account this computer forgets all it kept for it, the self-identity records included
 * (SelfIdentityEmailPinTest runs the store's half), and a lost answer with the session ended meanwhile offers to forget.
 */
class AccountDeletionWiringTest {
    private fun source(name: String): String =
        listOf(File("src/main/kotlin/io/silencelen/andvari/desktop/$name"), File("app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/$name"))
            .first { it.isFile }.readText()

    private val state = source("DesktopState.kt")
    private val ui = source("Ui.kt")

    private fun body(of: String): String = state.substringAfter(of).substringBefore("\n    }\n")

    @Test
    fun theStepsAreCoresAndTheComputerNamesItself() {
        assertTrue(state.contains("private val deletion = AccountDeletionFlow(DeletionCopy.COMPUTER)"))
        val delete = body("fun deleteAccount(email: String, password: String, code: String) {")
        assertTrue(delete.contains("deletion.refusal(email, stored.email, password, code, preview.totpRequired)"), "nothing is sent before the address matches")
        assertTrue(delete.contains("val outcome = deletion.delete(a, acct, email, password, code)"))
        assertTrue(ui.contains("is DesktopScreen.DeleteAccount -> DeleteAccountScreen(state)"))
        assertTrue(ui.contains("DeleteAccountCard(state)"), "Settings offers it")
        assertTrue(ui.contains("state.deletionForgetOffer?.let { DeletionForgetCard(state, it) }"))
    }

    @Test
    fun aDeletedAccountLeavesNothingOnThisComputer() {
        val delete = body("fun deleteAccount(email: String, password: String, code: String) {")
        assertTrue(delete.contains("DeletionOutcome.Deleted -> {\n                    forgetAccount(key, stored.userId, stored.email)"))
        // A lost answer while the stored session was cleared (a refused refresh): most likely the deletion's own end.
        assertTrue(delete.contains("val ended = api !== a || store.load()?.userId != stored.userId"))
        assertTrue(delete.contains("deletionForgetOffer = DeletionForgetOffer(key, stored.userId, stored.email, deletion.copy.MOST_LIKELY_DELETED)"))
        val forget = body("private fun forgetAccount(key: String, userId: String, email: String) {")
        for (wipe in listOf(
            "endSessionForDeletion()",
            "store.clearAccountKeys(key, userId)",
            "store.forgetSelfIdentity(key, userId, email)",
            "store.deleteNamespace(key, userId)",
            "if (store.load()?.userId == userId) store.clear()",
        )) {
            assertTrue(forget.contains(wipe), wipe)
        }
        val end = body("private fun endSessionForDeletion() {")
        // The usage buffer is dropped, not flushed: a deleted account's uses go nowhere.
        assertTrue(end.indexOf("clearUsage()") in 0 until end.indexOf("engine?.close()"))
        assertTrue(end.contains("pendingRecoverySecret?.fill(0)"))
        assertTrue(end.contains("screen = DesktopScreen.Welcome"))
        assertTrue(body("fun forgetDeletedAccount() {").contains("forgetAccount(offer.originKey, offer.userId, offer.email)"))
    }
}
