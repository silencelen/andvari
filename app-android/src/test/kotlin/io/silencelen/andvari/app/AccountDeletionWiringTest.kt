package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Delete account on the phone (spec 03 §13): the steps are core's AccountDeletionFlow (tested in core, with the iOS
 * controller running them against a server stand-in); these pin the phone's wiring around them. Settings offers it; a
 * session end heard while the request is on its way is held until it settles; once the server deleted the account the
 * phone forgets all it kept for it, the self-identity records included, so the address can register again here.
 */
class AccountDeletionWiringTest {
    private fun source(name: String): String =
        listOf(File("src/main/kotlin/io/silencelen/andvari/app/$name"), File("app-android/src/main/kotlin/io/silencelen/andvari/app/$name"))
            .first { it.isFile }.readText()

    private val vm = source("AndvariViewModel.kt")
    private val ui = source("MainActivity.kt")

    private fun body(of: String): String = vm.substringAfter(of).substringBefore("\n    }\n")

    @Test
    fun theStepsAreCoresAndThePhoneNamesItself() {
        assertTrue(vm.contains("private val deletion = AccountDeletionFlow(DeletionCopy.PHONE)"))
        assertTrue(body("fun deleteAccount(email: String, password: String, code: String) {").contains("deletion.refusal(email, stored.email, password, code, preview.totpRequired)"), "nothing is sent before the address matches")
        assertTrue(vm.contains("deletion.delete(live.api, live.account, email, password, code)"))
        assertTrue(ui.contains("is Screen.DeleteAccount -> DeleteAccountScreen(vm, ui)"))
        assertTrue(ui.contains("DeleteAccountCard(vm, ui)"), "Settings offers it")
        assertTrue(ui.contains("private val DELETION = io.silencelen.andvari.core.app.DeletionCopy.PHONE"))
    }

    @Test
    fun aSessionEndDuringTheRequestIsHeldUntilItSettles() {
        val idle = vm.substringAfter("fun checkIdleLock() {").substringBefore("// A-copyGate")
        assertTrue(idle.indexOf("if (deletionInFlight) return") in 0 until idle.indexOf("if (VaultSession.takeRejected())"), "held before it is taken")
        val delete = body("fun deleteAccount(email: String, password: String, code: String) {")
        assertTrue(delete.contains("deletionInFlight = true"))
        assertTrue(delete.contains("} finally {\n                deletionInFlight = false\n            }"))
        // Deleted: forgotten whatever ended the session meanwhile. Unknown with the session ended: most likely the
        // deletion's own end, so the sign-in screen offers to forget it; refused: the end was real.
        assertTrue(delete.contains("DeletionOutcome.Deleted -> {\n                    // Whatever ended the session meanwhile"))
        assertTrue(delete.contains("deletionForgetOffer = DeletionForgetOffer(originKey, stored.userId, stored.email, deletion.copy.MOST_LIKELY_DELETED)"))
        assertTrue(ui.contains("ui.deletionForgetOffer?.let { DeletionForgetCard(vm, it, busy = ui.busy) }"))
        // After an unknown outcome a later end is said as one that leaves the account's fate open.
        assertTrue(vm.contains("val reason = if (deletionUnknown) deletion.copy.SESSION_ENDED_OUTCOME_UNKNOWN else REASON_SESSION_ENDED"))
    }

    @Test
    fun aDeletedAccountLeavesNothingOnThePhone() {
        val forget = body("private fun forgetAccount(originKey: String, userId: String, email: String) {")
        // Uses first: the lock's flush would only be refused.
        assertTrue(forget.indexOf("UsageRecorder.clear()") in 0 until forget.indexOf("VaultSession.lock()"))
        for (wipe in listOf(
            "AppSignerBindings.clearAll(appContext)",
            "deleteCache(originKey, userId)",
            "QuickUnlock.wipe(cacheDir, originKey, userId)",
            "store.clearFullPasswordStamp(originKey, userId)",
            "store.clearAccountKeys(originKey)",
            "OriginNamespace.dir(cacheDir, originKey, userId).deleteRecursively()",
            "store.forgetSelfIdentity(originKey, userId, email)",
            "if (store.load()?.userId == userId) store.clear()",
            "VaultSession.takeRejected()",
        )) {
            assertTrue(forget.contains(wipe), wipe)
        }
        // The forget card runs the same wipe.
        assertTrue(body("fun forgetDeletedAccount() {").contains("forgetAccount(offer.originKey, offer.userId, offer.email)"))
        // The self-identity store forgets the binding only where it names that userId (core SelfIdentityPin.forget).
        assertTrue(source("Session.kt").contains("fun forgetSelfIdentity(originKey: String, userId: String, email: String) = selfIdentityStore(originKey).forget(userId, email)"))
    }
}
