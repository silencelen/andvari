package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The shared purge rules (core `PolicyCoordinator`) are pinned by `PolicyCoordinatorTest`. What only
 * Android can get wrong is calling them, and that is pinned here on the source, since the ViewModel
 * and the autofill entry points need a framework that JVM unit tests do not have.
 */
class PolicyCoordinatorWiringTest {
    private val src = File("src/main/kotlin/io/silencelen/andvari/app")
    private val vm = File(src, "AndvariViewModel.kt").readText()
    private val autofill = File(src, "autofill/AutofillUnlock.kt").readText()

    private fun span(of: String, from: String, to: String): String {
        val a = of.indexOf(from)
        assertTrue(a > -1, "missing: $from")
        val b = of.indexOf(to, a)
        assertTrue(b > a, "missing end: $to")
        return of.substring(a, b)
    }

    /** Gap 2: a refused refresh reaches the purge from every client that can hold the session. */
    @Test
    fun aDefinitiveInSessionRejectionFollowsThePurgePath() {
        assertTrue(vm.contains("onSessionRejected = coordinator::onRefreshRefused"), "the main app's token holders report a refused refresh")
        assertTrue(autofill.contains("onSessionRejected = coordinator::onRefreshRefused"), "and so does the autofill-only process's")
        assertFalse(vm.contains("OfflineData.purge") || autofill.contains("OfflineData.purge"), "every purge goes through the shared rules")
    }

    /** Gap 2: the UI half of the rejection. */
    @Test
    fun aRejectedSessionLandsOnTheSignInSurfaceAndDropsItsSecrets() {
        val end = span(vm, "private fun endRejectedSession()", "// ---- settings / server TOTP ----")
        for (secret in listOf("zeroPendingRecovery()", "zeroPendingRecover()", "pendingCaptureAuthKey = null", "closeEditor()", "importDismiss()")) {
            assertTrue(end.contains(secret), "$secret must die with the session")
        }
        assertTrue(end.contains("sessionCleared(REASON_SESSION_ENDED)"), "the F26 reason says why")
        assertTrue(end.contains("screen = Screen.Welcome"), "and the session is over, so the sign-in surface")
    }

    /**
     * The rejection reaches the screen whichever client heard it: the autofill unlock binds sessions the
     * main screen adopts, and its coordinator has no UI callback. Behaviour: `PolicyCoordinatorTest`.
     */
    @Test
    fun theScreenReportsARejectionWhicheverClientHeardIt() {
        val idle = span(vm, "fun checkIdleLock()", "fun backgroundSync()")
        val take = idle.indexOf("if (VaultSession.takeRejected()) {")
        assertTrue(take > -1, "the tick consumes the process-wide mark")
        assertTrue(take < idle.indexOf("lock(idleReason)"), "before the idle lock could report the dead session as idle")
        assertTrue(idle.substring(take, idle.indexOf("return", take)).contains("endRejectedSession()"), "and lands on the sign-in surface")
        assertTrue(vm.contains("viewModelScope.launch { checkIdleLock() }"), "the screen's own coordinator lands it at once")
        val signOut = span(vm, "fun signOut(reason: String? = null) {", "private fun endRejectedSession()")
        assertTrue(signOut.contains("VaultSession.takeRejected()"), "a refusal heard during sign-out is that sign-out, not a second event")
    }

    /** Finding 5: each client writes tokens only into the session it was built for. Behaviour: `TokenOwnerTest`. */
    @Test
    fun tokenWritesAreBoundToTheirSession() {
        assertTrue(vm.contains("{ store.updateTokensFor(owner, it) }"), "the main app's clients")
        assertTrue(autofill.contains("{ store.updateTokensFor(owner, it) }"), "the autofill unlock's client")
        assertFalse(vm.contains("{ store.updateTokens(it) }") || autofill.contains("{ store.updateTokens(it) }"), "an unbound write is the regression")
        assertTrue(Regex("""owner\.userId = s\.userId""").findAll(vm).count() == 2, "sign-in and enroll name the session they committed")
        // Review round 2: the client's own refresh token is part of the match (TokenOwnerTest), and the
        // compare and the write are one step: every writer of the stored session holds the same lock.
        assertTrue(vm.contains("heldRefreshToken = tokens?.refreshToken"))
        assertTrue(autofill.contains("heldRefreshToken = session.refreshToken"))
        val store = File(src, "Session.kt").readText()
        for (fn in listOf("override fun save(s: Session) {", "override fun updateTokens(t: Tokens?) {", "override fun clear() {", "override fun clearSessionTokens() {", "private fun backfillSessionOrigin() {", "override fun replaceTokensIf(")) {
            val body = span(store, fn, "\n    }\n")
            assertTrue(body.contains("synchronized(SESSION_LOCK)"), "$fn holds the session lock")
        }
        assertTrue(store.contains("private val SESSION_LOCK = Any()"), "one lock for every store in the process")
    }

    /** Gap 3: a forbidding policy seen by the poll, or found at bind, purges the whole namespace. */
    @Test
    fun aForbiddingPolicyIsEnforcedOnThePollAndAtBind() {
        val poll = span(vm, "runCatching { current.api.clientPolicy() }", "syncNow(current.engine)")
        assertTrue(poll.contains("if (applyPolicy(p, tag) && !p.offlineCacheAllowed) purgeOfflineData(originKey, current.account.userId)"), "only a reply that passed the fence may purge")
        val bind = span(vm, "private fun bind(a: AndvariApi", "notePasswordUnlockForQuickUnlockOffer()\n    }")
        val purge = bind.indexOf("if (!allowed) purgeOfflineData(originKey, acct.userId)")
        assertTrue(purge > -1, "bind drops the blob too, not just the file")
        assertTrue(bind.indexOf("VaultSession.bind(a, acct, newEngine, provenance)") in 0 until purge, "after the bind, so a replaced engine has released the file")
        assertFalse(bind.contains("deleteCache("), "the file-only delete is the regression")
        val af = span(autofill, "private suspend fun unlockLocked(", "val unlocked = VaultSession.get()")
        val afPurge = af.indexOf("if (!cacheAllowed) coordinator.purgeForbidden(originKey, acct.userId)")
        assertTrue(afPurge > -1, "the autofill unlock's cache path too")
        assertTrue(af.indexOf("VaultSession.bind(api, acct, engine, provenance)") in 0 until afPurge, "and after its bind")
        assertFalse(vm.contains("session != null && !bound) purgeOfflineData"), "start() no longer skips a bound session")
    }

    /** The bound the survey asked for: what the VM forwards to is the shared fetch and fence. */
    @Test
    fun theViewModelCallsTheSharedPolicyCode() {
        assertTrue(vm.contains("coordinator.boundedPolicy(probe)"))
        assertTrue(vm.contains("coordinator.probeIsCurrent(tag)"))
        assertTrue(vm.contains("if (!coordinator.applyPolicy(p, tag)) return false"))
        assertTrue(autofill.contains("coordinator.recordPolicy(originKey, p)"), "the autofill unlock's policy read uses the same mirrors")
    }
}
