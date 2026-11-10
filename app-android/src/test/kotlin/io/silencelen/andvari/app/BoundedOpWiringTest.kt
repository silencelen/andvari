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

    /** Step 6: the unlocks climb core's one ladder; their pins moved there with the code. */
    private val ladder = File("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/UnlockLadder.kt").readText()

    private fun coreSpan(of: String, from: String, to: String): String {
        val a = of.indexOf(from)
        assertTrue(a > -1, "span start missing: $from")
        val b = of.indexOf(to, a)
        assertTrue(b > a, "span end missing or out of order: $to")
        return of.substring(a, b)
    }

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
        val unlock = span("fun unlockWithBiometric(activity: FragmentActivity) = op(", "\n    }\n")
        assertTrue(unlock.contains("op(timeoutMs = null)"), "the prompt is not bounded by the op")
        assertTrue(unlock.contains("ladder.unlockWithQuick(session, ActivityHost(activity)"), "the shared ladder runs the prompt and the server half")
        val quick = coreSpan(ladder, "suspend fun unlockWithQuick(", "\n    }\n")
        assertTrue(quick.indexOf("quickKeys.recover(") in 0 until quick.indexOf("return climb("), "the server half runs after the prompt")
        val held = coreSpan(ladder, "private suspend fun underMutex(", "\n    }\n")
        assertTrue(held.contains("runBounded(BoundedOps.FLAT_MS) { api.accountKeys() }"), "and its server call is bounded")
    }

    /**
     * The unlock-class ops (sign-in, unlock, quick unlock, enroll) bound each server call up to bind(), not
     * the op: a whole-op bound firing after bind() showed an error over a live session, lost the capture-gate
     * decision and never revealed (or zeroed) a fresh enrollee's recovery phrase. Past bind() they always land.
     */
    @Test
    fun theUnlockClassOpsBoundEachServerCallAndAlwaysLand() {
        // Step 7: sign-in and enroll are core's (SessionEntry); their server legs and first sync are pinned there.
        val entry = File("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/SessionEntry.kt").readText()
        val signIn = span("fun signIn(email: String, password: String, totp: String? = null) = op(", "\n    fun unlock(email: String, password: String)")
        assertTrue(signIn.contains("timeoutMs = null)"), "no whole-op bound: it would fire after bind()")
        val coreSignIn = coreSpan(entry, "suspend fun signIn(", "\n    }\n")
        assertTrue(coreSignIn.contains("runBounded(BoundedOps.FLAT_MS) { a.prelogin(email) }"))
        assertTrue(coreSignIn.contains("runBounded(BoundedOps.FLAT_MS) { a.login(LoginRequest("))
        assertEntryLandsAfterTheFirstSync(coreSignIn, "return SignInResult.EndedBeforeLanding", "return SignInResult.SignedIn(")
        assertLandsOnTheEntrysVerdict(signIn, "SignInResult.EndedBeforeLanding -> ", "if (proof != null) startRecoveryCapture(proof) else toVault()")

        val unlock = span("fun unlock(email: String, password: String) = op(", "\n    // internal (A5c)")
        assertTrue(unlock.contains("timeoutMs = null)"))
        assertTrue(unlock.contains("ladder.unlockWithPassword(session, password,"), "the shared ladder")
        val held = coreSpan(ladder, "private suspend fun underMutex(", "\n    }\n")
        val keys = held.indexOf("runBounded(BoundedOps.FLAT_MS) { api.accountKeys() }")
        assertTrue(keys > -1, "a stall reads as offline")
        assertTrue(held.indexOf("} catch (e: IOException) {", keys) > keys && held.contains(".loadAccountKeys(stored.userId)"), "and opens on the cached keys")
        assertLandsOnTheLaddersVerdict(unlock, "startRecoveryCapture(authKey)")

        val quick = span("fun unlockWithBiometric(activity: FragmentActivity) = op(", "\n    }\n")
        assertLandsOnTheLaddersVerdict(quick, "toVault()\n                showFirstSync")

        // The ladder's own half: the first sync after the bind, outside the mutex, and the session's survival decides.
        val climb = coreSpan(ladder, "private suspend fun climb(", "\n    }\n")
        val mutex = climb.indexOf("session.withUnlockMutex { underMutex(")
        val sync = climb.indexOf("firstSyncAfterBind { options.firstSync(bound.unlocked.engine) }")
        assertTrue(mutex > -1 && sync > mutex, "the first sync runs after the bind, under its own bound")
        val live = climb.indexOf("if (!session.isLive(bound.unlocked.api)) return UnlockResult.EndedBeforeLanding", sync)
        assertTrue(live > sync, "the ladder checks its session survived the sync")
        assertTrue(climb.indexOf("return UnlockResult.Unlocked(", live) > live, "before it reports a landing")
        val bound = File("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/FirstSync.kt").readText()
        assertTrue(bound.contains("runBounded(BoundedOps.FLAT_MS) { sync() }"), "and that bound is the flat window")

        val enroll = span("private fun enrollOp(", "\n    // Shown-once recovery secret")
        assertTrue(enroll.contains("timeoutMs = null)"))
        val coreEnroll = coreSpan(entry, "suspend fun enroll(", "\n    }\n")
        assertTrue(coreEnroll.contains("runBounded(BoundedOps.FLAT_MS) { a.recoveryPubkey() }"))
        assertTrue(coreEnroll.contains("runBounded(BoundedOps.FLAT_MS) { a.register(enrolled.request) }"))
        assertTrue(coreEnroll.contains("try { coordinator.boundedPolicy(probe) } finally { probe.close() }"))
        assertEntryLandsAfterTheFirstSync(coreEnroll, "return EnrollOutcome.EndedBeforeLanding", "return EnrollOutcome.Enrolled(")
        assertLandsOnTheEntrysVerdict(enroll, "EnrollOutcome.EndedBeforeLanding -> ", "screen = Screen.RecoverySetup")
    }

    /**
     * Review round 2: the unlock mutex is shared with the autofill unlock, so waiting for it is a server
     * wait too. Every unlock path waits for it with a bound, and the autofill unlock neither calls the
     * server unbounded while holding it nor syncs inside it.
     */
    @Test
    fun theUnlockMutexIsNeverAnUnboundedWait() {
        assertTrue(!vm.contains("unlockMutex.withLock"), "the main app's unlock paths use the bounded wait")
        // Step 6: the main app's password and biometric unlocks and the autofill unlock's two all climb the
        // one ladder, which takes the mutex once, with the bounded wait.
        assertTrue(!vm.contains("withUnlockMutex") && vm.contains("ladder.unlockWithPassword(") && vm.contains("ladder.unlockWithQuick("), "password and biometric unlock")
        val autofill = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlock.kt").readText()
        assertTrue(!autofill.contains("unlockMutex.withLock") && !autofill.contains("withUnlockMutex"))
        assertTrue(autofill.contains(".unlockWithPassword(session, password, overlay)") && autofill.contains(".unlockWithQuick(session, ActivityHost(activity)"), "password and quick unlock")
        assertTrue(!ladder.contains("unlockMutex.withLock"))
        assertTrue(Regex("""session\.withUnlockMutex \{""").findAll(ladder).count() == 1, "one mutex, taken in one place")
        val held = coreSpan(ladder, "private suspend fun underMutex(", "\n    }\n")
        assertTrue(held.contains("refreshPolicy(api, originKey, stored.userId)") && held.contains("runBounded(BoundedOps.FLAT_MS) { api.accountKeys() }"), "its calls under the mutex are bounded")
        assertTrue(coreSpan(ladder, "private suspend fun refreshPolicy(", "\n    }\n").contains("coordinator.boundedPolicy(api)"), "the policy read too")
        assertTrue(!held.contains(".sync()") && !held.contains("firstSync"), "and its first sync is not under the mutex")
        val climb = coreSpan(ladder, "private suspend fun climb(", "\n    }\n")
        assertTrue(climb.indexOf("firstSyncAfterBind {") > climb.indexOf("session.withUnlockMutex {"), "it runs after, bounded")
        // A session that ended in it is never handed to the fill.
        val landed = coreSpan(autofill, "private fun landed(r: UnlockResult)", ".also { AutofillHardLock.arm() }")
        assertTrue(landed.contains("UnlockResult.EndedBeforeLanding -> throw ApiException(401, \"session_ended\""), "and a session that ended in it is never handed to the fill")
    }

    /** Step 7: core's sign-in and enroll run the first sync after the bind and report a session that ended in it. */
    private fun assertEntryLandsAfterTheFirstSync(body: String, ended: String, landed: String) {
        val bind = body.indexOf("binder.bind(")
        val sync = body.indexOf("firstSyncAfterBind { firstSync(c.unlocked.engine) }")
        assertTrue(bind > -1 && sync > bind, "the first sync after the bind runs under its own bound")
        val live = body.indexOf("if (!session.isLive(a))", sync)
        assertTrue(live > sync && body.indexOf(ended, live) > live, "the entry checks its session survived the sync")
        assertTrue(body.indexOf(landed, live) > live, "before it reports a landing")
    }

    /** Step 7: the app lands sign-in and enroll where core's verdict says, after the first sync it ran. */
    private fun assertLandsOnTheEntrysVerdict(body: String, ended: String, landing: String) {
        assertTrue(body.contains("firstSync = { syncNow(it) }"), "the app's own sync, under core's bound")
        val e = body.indexOf(ended)
        assertTrue(e > -1 && body.indexOf("sessionEndedBeforeLanding()", e) > e, "a session that ended in the first sync lands nowhere")
        val land = body.indexOf(landing)
        assertTrue(land > -1, "lands: $landing")
        assertTrue(body.indexOf("showFirstSync(r.firstSync)", land) > land, "what the sync could not do is said on the landing")
    }

    /** Step 6: an unlock lands where the ladder's verdict says, after the first sync it ran. */
    private fun assertLandsOnTheLaddersVerdict(body: String, landing: String) {
        assertTrue(body.contains("UnlockOptions(firstSync = { syncNow(it) })"), "the app's own sync, under the ladder's bound")
        val ended = body.indexOf("UnlockResult.EndedBeforeLanding -> ")
        assertTrue(ended > -1 && body.indexOf("sessionEndedBeforeLanding()", ended) > ended, "a session that ended in the first sync lands nowhere")
        val land = body.indexOf(landing)
        assertTrue(land > -1, "lands: $landing")
        assertTrue(body.indexOf("showFirstSync(r.firstSync)", land) > land, "what the sync could not do is said on the landing")
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
            "runBounded(BoundedOps.FLAT_MS) { block() }",
            // The pre-session legs that hold busy too: the manual switch probe (below) and both recovery steps.
            "runBounded(BoundedOps.RECOVERY_CALL_MS) { a.recoverySelfVerify(email.trim(), authKey) }",
            "boundedPolicy(a).let { requireCurrentPolicy(it, applyPolicy(it, policyTag)) }",
            "runBounded(BoundedOps.RECOVERY_CALL_MS) { a.recoverySelfCommit(commit) }",
        )) {
            assertTrue(vm.contains(pin), "must stay bounded: $pin")
        }
        // The §F.9 capture's commit and confirm hold busy too; they moved to core with the capture (step 7).
        val capture = File("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/RecoveryCapture.kt").readText()
        assertTrue(capture.contains("runBounded(BoundedOps.RECOVERY_CALL_MS) { live.api.recoverySelfSetup(setup.request) }"), "must stay bounded: the capture's commit")
        assertTrue(capture.contains("runBounded(BoundedOps.RECOVERY_CALL_MS) { live.api.recoverySelfConfirm(pieceId) }"), "must stay bounded: the capture's confirm")
        assertTrue(vm.contains("when (val r = capture.setup(live, authKey))") && vm.contains("when (capture.confirm(live, pieceId))"), "the app's capture is core's")
        // The manual switch's probe holds busy too; it moved to core with the switch (step 5).
        assertTrue(vm.contains("when (val r = serverSwitch.connect(target))"), "the app's Connect is core's")
        val switch = File("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/ServerSwitch.kt").readText()
        assertTrue(switch.substringAfter("suspend fun connect(").substringBefore("fun moveTo(").contains("coordinator.boundedPolicy(probe)"), "and its probe is bounded")
        // A stalled pre-export sync reads as offline, on both paths.
        assertTrue(Regex("""runBounded\(BoundedOps\.FLAT_MS\) \{ syncNow\(e\) \}""").findAll(vm).count() >= 2, "backupBegin and csvBegin")
    }
}
