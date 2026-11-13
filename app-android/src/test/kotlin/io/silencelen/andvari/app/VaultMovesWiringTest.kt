package io.silencelen.andvari.app

import io.silencelen.andvari.core.app.VaultMoves
import io.silencelen.andvari.core.client.VaultInfo
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Round-6 review L6: the vault rules are ONE implementation, core's [VaultMoves], which the iOS controller uses too.
 * The ViewModel needs an Application, so what Android now does is proved twice: the rules themselves, run here as the
 * Android screens call them, and the wiring, pinned on the source. The decided results:
 *  - a target (and a new item's or an import's vault) must be writable WITH its key held (canSealUnder);
 *  - an item in a vault this account only reads can be copied out, not moved (Move is not offered);
 *  - an unfinished try is kept until done or cancelled: Cancel/dismiss drops it, a lock keeps it sealed in
 *    app-private storage (never in memory), a sign-out or an ended session drops it.
 */
class VaultMovesWiringTest {
    private val vm = File("src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText()
    private val main = File("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText()
    private val sharing = File("src/main/kotlin/io/silencelen/andvari/app/SharingScreen.kt").readText()

    private fun span(of: String, from: String, to: String): String {
        val a = of.indexOf(from)
        assertTrue(a > -1, "span start missing: $from")
        val b = of.indexOf(to, a)
        assertTrue(b > a, "span end missing or out of order: $to")
        return of.substring(a, b)
    }

    private val vaults = listOf(
        VaultInfo("p", "personal", "Personal", null),
        VaultInfo("r", "shared", "Read only", "reader"),
        VaultInfo("w", "shared", "Family", "writer"),
        VaultInfo("k", "shared", "No key here", "owner"),
    )
    private val holds = setOf("p", "r", "w")

    @Test
    fun theRulesAsAndroidCallsThem() {
        assertEquals(listOf("p", "w"), VaultMoves.writableVaults(vaults) { it in holds }.map { it.vaultId }, "never a reader's vault, never one whose key is not held")
        assertEquals(listOf("p", "w"), VaultMoves.targets("r", vaults) { it in holds }.map { it.vaultId }, "a reader's item can be copied out")
        assertFalse(VaultMoves.canTakeOut("r", vaults), "but not moved")
        assertTrue(VaultMoves.canTakeOut("w", vaults))
        assertEquals(listOf("w"), VaultMoves.targets("p", vaults) { it in holds }.map { it.vaultId })
    }

    @Test
    fun theViewModelCallsTheSharedRulesAndKeepsNoRulesOfItsOwn() {
        assertTrue(vm.contains("fun writableVaults(): List<VaultInfo> = VaultMoves.writableVaults(vaultInfos()) { account?.canSealUnder(it) == true }"))
        assertTrue(vm.contains("fun moveTargets(item: VaultItem): List<VaultInfo> = VaultMoves.targets(item.vaultId, vaultInfos()) { account?.canSealUnder(it) == true }"))
        assertTrue(vm.contains("fun canMoveOut(item: VaultItem): Boolean = VaultMoves.canTakeOut(item.vaultId, vaultInfos())"))
        assertFalse(vm.contains("moveGestures"), "no memo of its own")
        val move = span(vm, "fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean) {", "\n    // ---- ")
        assertTrue(move.contains("if (move && !canMoveOut(current))"), "a move needs the source writable")
        assertTrue(move.contains("if (moveTargets(current).none { it.vaultId == targetVaultId })"), "the target must be one of the shared targets")
        assertTrue(move.contains("moves.prepare(e, current, targetVaultId, move) { runBounded(BoundedOps.FLAT_MS) { e.sync() } }"), "a kept copy is checked after a sync (round-7 M3)")
        assertTrue(move.contains("is VaultMoves.Prepared.AlreadyCopied ->"), "an earlier try's copy is never made again")
        assertTrue(move.contains("moves.finished(itemId, targetVaultId, move)"))
        assertTrue(move.contains("moves.failed(itemId, targetVaultId, move, t)"))
        assertTrue(move.contains("VaultMoves.bothVaultsLine(failed, item, target, source)"), "the message names the copy and where it went")
    }

    @Test
    fun anUnfinishedTryIsKeptUntilDoneOrCancelledSealedAcrossALock() {
        assertTrue(vm.contains("""private val moves = VaultMoves(VaultMoves.Store.Sealed(AppPrivateFile(File(cacheDir, "move-memos.bin"))) { account })"""))
        assertTrue(span(vm, "fun closeMovePicker() {", "\n    }\n").contains("movePickerItemId?.let(moves::cancelled)"), "Cancel/dismiss drops it")
        assertTrue(vm.contains("moves.forget() // L5"), "a lock keeps it, sealed, out of memory")
        assertEquals(2, Regex("""moves\.drop\(\)""").findAll(vm).count(), "a sign-out and an ended session drop it")
    }

    @Test
    fun theScreensAskTheViewModel() {
        assertTrue(main.contains("val moveTargets = vm.moveTargets(item)"))
        assertTrue(main.contains("MoveCopyControl(vm, ui, item, moveTargets, canMove = vm.canMoveOut(item))"))
        assertFalse(main.contains("""it.type == "personal" || it.role == "owner" || it.role == "writer""""), "no copy of the rule in the screens")
        assertEquals(2, Regex("""vm\.writableVaults\(\)""").findAll(main).count(), "the editor's and the import's vault choices")
        // Offered to a reader too: the control sits after the editable-only block closes, not inside it.
        val detail = span(main, "if (!readOnly) {\n            var confirmDelete", "val moveTargets = vm.moveTargets(item)")
        assertTrue(detail.contains("\n            }\n        }\n        // F19 (design §8)"), "the if (!readOnly) block closes before the move/copy control")
        assertTrue(sharing.contains("""if (canMove) TextButton(onClick = { vm.openMovePicker(item.itemId, "move") }) { Text("Move to vault…") }"""), "Move only where the item can leave its vault")
    }
}
