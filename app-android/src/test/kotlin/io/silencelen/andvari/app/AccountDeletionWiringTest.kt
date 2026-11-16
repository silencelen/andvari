package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Delete account on the phone (spec 03 §13): the steps are core's AccountDeletionFlow (tested in core, with the iOS
 * controller running them against a server stand-in); these pin the phone's wiring around them. Settings offers it; a
 * session end heard while the request is on its way is held until it settles; once the server deleted the account the
 * phone is left as a fresh install: nothing of the account, and nothing of its server.
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
    fun aDeletedAccountLeavesThePhoneAsAFreshInstall() {
        val forget = body("private fun forgetAccount(originKey: String, userId: String) {")
        // Uses first: the lock's flush would only be refused.
        assertTrue(forget.indexOf("UsageRecorder.clear()") in 0 until forget.indexOf("VaultSession.lock()"))
        // The account, then every namespace at its server (each quick-unlock key before its directory), then the server.
        val steps = listOf(
            "VaultSession.lock()",
            "AppSignerBindings.clearAll(appContext)",
            "moves.drop()",
            "AutofillDebugLog.forget(appContext)",
            "QuickUnlock.wipe(cacheDir, originKey, userId)",
            "AndroidNamespaceStorage(cacheDir).deleteOrigin(originKey)",
            "store.forgetServer(originKey)",
            "coordinator.originChanged()",
            "VaultSession.takeRejected()",
        )
        var at = -1
        for (step in steps) {
            val next = forget.indexOf(step, at + 1)
            assertTrue(next > at, "$step, in this order")
            at = next
        }
        // The sign-in screen then shows the server the phone dials now, as at a launch, and probes its policy.
        val land = body("private fun landSignedOut(notice: String) {")
        assertTrue(land.contains("baseUrl = store.baseUrl, policy = null, policyFetchFailed = false, lastExportAt = store.lastExportAt,"))
        assertTrue(land.contains("serverSwitch.probePolicy()"))
        // The forget card runs the same wipe.
        val card = body("fun forgetDeletedAccount() {")
        assertTrue(card.contains("forgetAccount(offer.originKey, offer.userId)") && card.contains("landSignedOut(deletion.copy.FORGOTTEN)"))
    }

    /** The store's half is SharedPreferences, which this JVM has none of: what it removes, read from its source. */
    @Test
    fun theStoreForgetsTheServerInOneWrite() {
        val forget = source("Session.kt").substringAfter("override fun forgetServer(originKey: String) {").substringBefore("\n    }\n")
        assertTrue(forget.contains("""edit.remove("userId").remove("email").remove("accessToken").remove("refreshToken").remove(SESSION_ORIGIN).remove("mustChangePassword")"""))
        assertTrue(forget.contains("""val prefix = ns(originKey, "")"""))
        assertTrue(forget.contains("for (key in prefs.all.keys) if (key.startsWith(prefix)) edit.remove(key)"), "everything under the origin, whoever's")
        assertTrue(forget.contains("""if (currentOriginKey() == originKey) edit.remove("baseUrl").remove("pendingServer").remove("lastSyncAt").remove("lastExportAt")"""), "the default server again")
        assertTrue(forget.contains("edit.commit()"), "one synchronous write: nothing is left for a process started right after")
        // The device's own stays: the clock ratchet and the one-shot migration flags are never removed here.
        for (kept in listOf("qu_highWater", "nsAdoptedOnce", "baseUrlMigratedPublic")) assertTrue(!forget.contains(kept), kept)
    }

    /** The files' half runs here: every user's namespace at the server goes, another server's stays. */
    @Test
    fun everyNamespaceAtTheServerGoesAndAnotherServersStays() {
        val base = java.nio.file.Files.createTempDirectory("andvari-android-deletion").toFile()
        try {
            val home = OriginNamespace.originKey("https://vault.example.net")
            val other = OriginNamespace.originKey("https://example.org")
            for ((origin, user) in listOf(home to "u1", home to "u2", other to "u1")) {
                val ns = OriginNamespace.dir(base, origin, user).apply { mkdirs() }
                File(ns, "vault-$user.db").writeText("ciphertext")
                File(ns, "vault-$user.db-wal").writeText("ciphertext")
                File(ns, "quick-unlock-$user.json").writeText("{}")
                PersonalDeviceState.open(base, origin, user).set("personal.last", "v-personal")
            }
            val users = AndroidNamespaceStorage(base).deleteOrigin(home)
            assertTrue(users.sorted() == listOf("u1", "u2"), "the users it held a namespace for: $users")
            assertTrue(!File(File(base, "ns"), home).exists(), "caches, device states and quick-unlock blobs, whoever's")
            assertTrue(File(OriginNamespace.dir(base, other, "u1"), "vault-u1.db").isFile, "another server's namespace is not this deletion's (§4.2)")
            assertTrue(PersonalDeviceState.open(base, other, "u1").get("personal.last") == "v-personal")
            assertTrue(AndroidNamespaceStorage(base).deleteOrigin(home).isEmpty(), "idempotent")
        } finally {
            base.deleteRecursively()
        }
    }
}
