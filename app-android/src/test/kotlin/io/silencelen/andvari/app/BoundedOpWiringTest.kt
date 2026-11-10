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
        assertTrue(unlock.indexOf("QuickUnlock.recoverUvk") < unlock.indexOf("runBounded(BoundedOps.AUTH_OP_MS)"), "the network half runs bounded, after the prompt")
        assertTrue(unlock.contains("finishBiometricUnlock("))
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
        )) {
            assertTrue(vm.contains(pin), "must stay bounded: $pin")
        }
        // A stalled pre-export sync and a stalled post-unlock sync read as offline, on both paths.
        assertTrue(Regex("""runBounded\(BoundedOps\.FLAT_MS\) \{ syncNow\(e\) \}""").findAll(vm).count() >= 2, "backupBegin and csvBegin")
        assertTrue(Regex("""runCatching \{ runBounded\(BoundedOps\.FLAT_MS\) \{ syncNow\(engine!!\) \} \}""").findAll(vm).count() >= 2, "password and biometric unlock")
    }
}
