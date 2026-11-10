package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Audit H10, the Android half: [UiState.busy] defers the idle lock, so every op that holds it must
 * have a whole-call bound. The ViewModel needs an Application, so the rule lives in core
 * (`BoundedOpTest` pins the runner and its budgets) and the wiring is pinned here on the source.
 */
class BoundedOpWiringTest {
    private val vm = File("src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText()

    /** The slice of the source from [from] to the next [to], both asserted present. */
    private fun span(from: String, to: String): String {
        val a = vm.indexOf(from)
        assertTrue(a > -1, "span start missing: $from")
        val b = vm.indexOf(to, a)
        assertTrue(b > a, "span end missing or out of order: $to")
        return vm.substring(a, b)
    }

    @Test
    fun everyOpRunsUnderTheBoundByDefault() {
        val op = span("private fun op(", "\n    }\n")
        assertTrue(op.contains("timeoutMs: Long? = BoundedOps.FLAT_MS"), "the default is the flat window")
        assertTrue(op.contains("runBounded(timeoutMs) { block() }"), "op runs its block under the bound")
    }

    /** The biometric prompt waits on a person, so only its server legs are bounded. */
    @Test
    fun theBiometricPromptIsExemptAndTheNetworkLegsAreNot() {
        val unlock = span("fun unlockWithBiometric(activity: FragmentActivity) = op(", "private suspend fun finishBiometricUnlock")
        assertTrue(unlock.contains("op(timeoutMs = null)"), "the prompt is not bounded by the op")
        assertTrue(unlock.indexOf("QuickUnlock.recoverUvk") < unlock.indexOf("finishBiometricUnlock(session, originKey, uvk)"), "the server half runs after the prompt")
        val finish = span("private suspend fun finishBiometricUnlock", "\n    }\n")
        assertTrue(finish.contains("runBounded(BoundedOps.FLAT_MS) { a.accountKeys() }"), "and its server call is bounded")
    }

    /**
     * The unlock-class ops (sign-in, unlock, quick unlock, enroll) bound each server call up to bind(), not
     * the op: a whole-op bound firing after bind() showed an error over a live session, lost the capture-gate
     * decision and never revealed (or zeroed) a fresh enrollee's recovery phrase. Past bind() they always land.
     */
    @Test
    fun theUnlockClassOpsBoundEachServerCallAndAlwaysLand() {
        val signIn = span("fun signIn(email: String, password: String, totp: String? = null) = op(", "\n    fun unlock(email: String, password: String)")
        assertTrue(signIn.contains("timeoutMs = null)"), "no whole-op bound: it would fire after bind()")
        assertTrue(signIn.contains("runBounded(BoundedOps.FLAT_MS) { a.prelogin(email) }"))
        assertTrue(signIn.contains("runBounded(BoundedOps.FLAT_MS) { a.login(LoginRequest("))
        assertLandsAfterTheFirstSync(signIn, "if (gate) startRecoveryCapture(authKey) else toVault()")

        val unlock = span("fun unlock(email: String, password: String) = op(", "\n    // internal (A5c)")
        assertTrue(unlock.contains("timeoutMs = null)"))
        assertTrue(unlock.contains("runBounded(BoundedOps.FLAT_MS) { a.accountKeys() }"), "a stall reads as offline and opens on the cached keys")
        assertLandsAfterTheFirstSync(unlock, "startRecoveryCapture(authKey)")

        val quick = span("private suspend fun finishBiometricUnlock", "\n    }\n")
        assertLandsAfterTheFirstSync(quick, "toVault()")

        val enroll = span("private fun enrollOp(", "\n    // Shown-once recovery secret")
        assertTrue(enroll.contains("timeoutMs = null)"))
        assertTrue(enroll.contains("runBounded(BoundedOps.FLAT_MS) { a.recoveryPubkey() }"))
        assertTrue(enroll.contains("runBounded(BoundedOps.FLAT_MS) { a.register(req) }"))
        assertTrue(enroll.contains("try { boundedPolicy(probe) } finally { probe.close() }"))
        assertLandsAfterTheFirstSync(enroll, "screen = Screen.RecoverySetup")
    }

    /**
     * Review round 2: the unlock mutex is shared with the autofill unlock, so waiting for it is a server
     * wait too. Every unlock path waits for it with a bound, and the autofill unlock neither calls the
     * server unbounded while holding it nor syncs inside it.
     */
    @Test
    fun theUnlockMutexIsNeverAnUnboundedWait() {
        assertTrue(!vm.contains("unlockMutex.withLock"), "the main app's unlock paths use the bounded wait")
        assertTrue(Regex("""VaultSession\.withUnlockMutex \{""").findAll(vm).count() == 2, "password and biometric unlock")
        val autofill = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlock.kt").readText()
        assertTrue(!autofill.contains("unlockMutex.withLock"))
        assertTrue(Regex("""VaultSession\.withUnlockMutex \{""").findAll(autofill).count() == 2, "password and quick unlock")
        val locked = autofill.substringAfter("private suspend fun unlockLocked(").substringBefore("\n}\n")
        assertTrue(locked.contains("coordinator.boundedPolicy(api)") && locked.contains("runBounded(BoundedOps.FLAT_MS) { api.accountKeys() }"), "its calls under the mutex are bounded")
        assertTrue(!locked.contains("engine.sync()"), "and its first sync is not under the mutex")
        assertTrue(autofill.contains("runBounded(BoundedOps.FLAT_MS) { r.unlocked.engine.sync() }"), "it runs after, bounded")
        val after = autofill.substringAfter("private suspend fun syncOutsideTheMutex(")
        assertTrue(after.indexOf("if (!VaultSession.isLive(r.unlocked.api)) throw") in 0 until after.indexOf("return r.unlocked"), "and a session that ended in it is never handed to the fill")
    }

    private fun assertLandsAfterTheFirstSync(body: String, landing: String) {
        val sync = body.indexOf("firstSyncAfterBind { syncNow(engine!!) }")
        assertTrue(sync > -1, "the first sync after bind() runs under its own bound")
        // Review round 2: a rejection during that sync ends the session; the op must not land on it.
        val live = body.indexOf("isLive", sync)
        assertTrue(live > sync, "the op checks its session survived the sync")
        assertTrue(body.indexOf("sessionEndedBeforeLanding()", sync) in sync until body.indexOf(landing, sync), "before it lands")
        assertTrue(body.indexOf(landing, sync) > live, "and the landing follows it whatever it did: $landing")
        assertTrue(body.indexOf("showFirstSync(first)", sync) > sync, "what the sync could not do is said on the landing")
    }

    @Test
    fun theOtherBusyHoldingLegsAreBounded() {
        for (pin in listOf(
            // Scaled to the bytes they carry.
            "saveItem(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload> = emptyList(), vaultId: String? = null, onSaved: () -> Unit = {}) = op(mapError = HouseholdCopy::forSaveError, timeoutMs = BoundedOps.attachmentMs(uploads.sumOf { it.data.size.toLong() }))",
            "runBounded(BoundedOps.attachmentMs(current.doc.attachments.sumOf { it.size }))",
            "runBounded(BoundedOps.attachmentMs(ref.size))",
            "runBounded(BoundedOps.attachmentMs(p.ref.size))",
            "runBounded(BoundedOps.importMs(plan.items.size))",
            "runBounded(BoundedOps.rescueCopyMs(bytes, count))",
            // Small JSON under busy.
            "runBounded(BoundedOps.RECOVERY_CALL_MS) { a.recoverySelfSetup(setup.request) }",
            "runBounded(BoundedOps.RECOVERY_CALL_MS) { a.recoverySelfConfirm(pieceId) }",
            "runBounded(BoundedOps.FLAT_MS) { block() }",
            // The pre-session legs that hold busy too: the manual switch probe (below) and both recovery steps.
            "runBounded(BoundedOps.RECOVERY_CALL_MS) { a.recoverySelfVerify(email.trim(), authKey) }",
            "boundedPolicy(a).let { requireCurrentPolicy(it, applyPolicy(it, policyTag)) }",
            "runBounded(BoundedOps.RECOVERY_CALL_MS) { a.recoverySelfCommit(commit) }",
        )) {
            assertTrue(vm.contains(pin), "must stay bounded: $pin")
        }
        // The manual switch's probe holds busy too; it moved to core with the switch (step 5).
        assertTrue(vm.contains("when (val r = serverSwitch.connect(target))"), "the app's Connect is core's")
        val switch = File("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/ServerSwitch.kt").readText()
        assertTrue(switch.substringAfter("suspend fun connect(").substringBefore("fun moveTo(").contains("coordinator.boundedPolicy(probe)"), "and its probe is bounded")
        // A stalled pre-export sync reads as offline, on both paths.
        assertTrue(Regex("""runBounded\(BoundedOps\.FLAT_MS\) \{ syncNow\(e\) \}""").findAll(vm).count() >= 2, "backupBegin and csvBegin")
    }
}
