package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.unit.Density
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Nothing moves under a control a person is about to use. A line that appears while typing, or
 * that a read adds, sits in a slot of a fixed height, and a list a read changes sits in a box of a fixed height. The
 * forms are laid out headlessly (one frame of an image scene) and the place of the control below is compared; the
 * screens that need the whole model are pinned to their slots in the source.
 */
class NothingMovesTest {
    /** Lay [content] out once at [width] px and return where each [mark]ed control's top is. */
    @OptIn(ExperimentalComposeUiApi::class)
    private fun tops(width: Int = 420, content: @Composable (Marks) -> Unit): Map<String, Float> {
        val marks = Marks()
        val scene = ImageComposeScene(width, 3000, Density(1f)) { MaterialTheme { Column { content(marks) } } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
        return marks.tops
    }

    private class Marks {
        val tops = HashMap<String, Float>()

        @Composable
        fun Mark(name: String, content: @Composable () -> Unit) =
            Box(Modifier.onGloballyPositioned { tops[name] = it.positionInRoot().y }) { content() }
    }

    private val passwords = listOf("", "a", "Password1", "correct horse battery staple", "pässwordpässwordpässword-123!")

    @Test
    fun theSecondPasswordFieldDoesNotMoveWhileTheFirstIsTyped() {
        val second = passwords.map { pw ->
            assertNotNull(tops { m ->
                SecretField(UiText.Plain("new"), pw) {}
                MasterPasswordStrengthHints(pw)
                m.Mark("again") { SecretField(UiText.Plain("again"), "") {} }
            }["again"])
        }
        assertEquals(1, second.toSet().size, "the second field's top for each password typed: $second")
        // The same at the narrowest width, where every line wraps.
        val narrow = passwords.map { pw -> assertNotNull(tops(width = 260) { m -> MasterPasswordStrengthHints(pw); m.Mark("again") { Text("x") } }["again"]) }
        assertEquals(1, narrow.toSet().size, "$narrow")
    }

    @Test
    fun theSecondPassphraseFieldOfAnExportDoesNotMoveEither() {
        val second = passwords.map { pw -> assertNotNull(tops { m -> PassphraseStrength(pw); m.Mark("again") { Text("x") } }["again"]) }
        assertEquals(1, second.toSet().size, "$second")
    }

    @Test
    fun aSlotKeepsItsHeightAndAListBoxKeepsItsHeightWhateverIsInThem() {
        val slot = listOf(0, 1, 3, 12).map { n ->
            assertNotNull(tops { m -> FixedSlot(CONSOLE_HEADER_SLOT) { repeat(n) { Text("a line a read added, $it") } }; m.Mark("below") { Text("x") } }["below"])
        }
        assertEquals(1, slot.toSet().size, "$slot")
        // The console's header: as tall as what stands in it (no room kept for a warning that is not there), and never
        // taller than its room, past which its lines scroll inside.
        val header = listOf(1, 2, 12, 30).map { n ->
            assertNotNull(tops { m -> CappedSlot(CONSOLE_HEADER_SLOT) { repeat(n) { Text("a line a read added, $it") } }; m.Mark("below") { Text("x") } }["below"])
        }
        assertTrue(header[0] < header[1], "one line takes less room than two: $header")
        assertEquals(header[2], header[3], "many lines stop at the room: $header")
        assertTrue(header[1] < header[2], "$header")
        val box = listOf(0, 1, 5, 40).map { n ->
            assertNotNull(tops { m -> ListBox(ACCOUNTS_BOX) { repeat(n) { Text("row $it") } }; m.Mark("below") { Text("x") } }["below"])
        }
        assertEquals(1, box.toSet().size, "$box")
        // The sign-in title, which names the address as it is typed.
        val title = listOf("", "Master password for b@x.example on Family (https://family.example)", "Master password for " + "a".repeat(120) + "@x.example on Family").map { t ->
            assertNotNull(tops { m -> FixedSlot(SIGN_IN_TITLE_SLOT) { Text(t, style = MaterialTheme.typography.bodyLarge) }; m.Mark("below") { Text("x") } }["below"])
        }
        assertEquals(1, title.toSet().size, "$title")
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    /** Every form with a password field, each place a line can come or go near one, pinned to its slot. */
    @Test
    fun everyFormWithAPasswordFieldHasItsLinesInSlots() {
        assertTrue(body(src("TrustUi.kt"), "internal fun MasterPasswordStrengthHints(").contains("FixedSlot(STRENGTH_SLOT)"))
        assertTrue(body(src("VaultTransferScreens.kt"), "internal fun PassphraseStrength(").contains("FixedSlot(STRENGTH_SLOT)"))
        // The three forms with a new master password use the slotted hints between their two fields.
        for ((file, head) in listOf("AccountEntryScreens.kt" to "internal fun CreateAccountScreen(", "LinkAndRecoveryScreens.kt" to "internal fun ReplacePasswordScreen(", "SettingsScreens.kt" to "internal fun ChangePasswordSection(")) {
            val b = body(src(file), head)
            val first = b.indexOf("Placeholder.NEW_PASSWORD_FIELD")
            val hints = b.indexOf("MasterPasswordStrengthHints(")
            val again = b.indexOf("Placeholder.NEW_PASSWORD_AGAIN_FIELD")
            assertTrue(first in 0 until hints && hints < again, "$file: $first $hints $again")
        }
        assertTrue(body(src("SettingsScreens.kt"), "internal fun ChangePasswordSection(").contains("FixedSlot(MISMATCH_SLOT) { if (again.isNotEmpty() && again != replacement)"))
        assertTrue(body(src("AccountEntryScreens.kt"), "internal fun SignInScreen(").contains("FixedSlot(SIGN_IN_TITLE_SLOT) { SignInNaming(screen, email) }"))
        val unlock = src("AccountScreens.kt")
        assertTrue(unlock.contains("FixedSlot(UNLOCK_SAID_SLOT) {\n            if (s.busy) Quiet(UiText.ph(Placeholder.UNLOCKING))\n            SaidHere(model, s)"))
        assertTrue(src("VaultItemsScreens.kt").contains("FixedSlot(CARD_WARNING_SLOT) {\n                guardedRead(editedVault, null) { c.cardNumberWarning(number) }"))
        val devices = body(src("SettingsScreens.kt"), "internal fun DevicesSection(")
        assertTrue(devices.indexOf("ListBox(DEVICES_BOX)") in 0 until devices.indexOf("MasterPasswordField("))
        val export = src("VaultTransferScreens.kt")
        assertTrue(export.substringAfter("FixedSlot(EXPORT_SAID_SLOT) {").substringBefore("Main(UiText.ph(Placeholder.EXPORT_CHOOSE_PLACE)").contains("Say(Placeholder.WORKING)"))
    }

    /** The deletion's code field that the server asks for only after a try comes under Delete, which does not move. */
    @Test
    fun aCodeAskedForAfterTheDeletionsTryComesUnderTheButton() {
        val del = body(src("SettingsScreens.kt"), "internal fun DeleteAccountSection(")
        assertTrue(del.contains("val codeLate = codeWanted && !plan.codeNeeded"))
        val button = del.indexOf("Main(UiText.ph(Placeholder.DELETION_CONFIRM)")
        assertTrue(del.indexOf("if (codeWanted && !codeLate) Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD)") in 0 until button, "a planned code above it")
        assertTrue(del.indexOf("if (codeLate) Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD)") > button, "a late one under it")
    }

    /** The console: every line a read can add above its lists is in the header's slot, and each list is in its box. */
    @Test
    fun theConsolesLinesAndListsAreInSlotsAndBoxes() {
        val screens = src("OperatorScreens.kt")
        val header = body(screens, "private fun ConsoleHeader(")
        val slot = header.substringAfter("CappedSlot(CONSOLE_HEADER_SLOT) {").substringBefore("Quieter(UiText.ph(Placeholder.OP_READ_AGAIN)")
        for (line in listOf("c.setupUnfinished", "it.stalled", "c.serverSentBadRowsLine", "c.status?.let")) assertTrue(slot.contains(line), line)
        // What a read answered sits beside its control, in a slot of the row's own height: nothing moves, no gap under it.
        val beside = body(screens, "private fun WithSaidBeside(")
        assertTrue(beside.contains("Row(") && beside.contains(".height(CONSOLE_SAID_SLOT)") && beside.contains("verticalScroll("))
        val again = header.substringAfter("WithSaidBeside({ Quieter(UiText.ph(Placeholder.OP_READ_AGAIN)")
        assertTrue(again.contains("OperatorSaid(op, OperatorModel.Area.CONSOLE, anyAction = true)"))
        val accounts = body(screens, "private fun AccountsSection(")
        assertTrue(accounts.contains("ListBox(ACCOUNTS_BOX) { AccountRows("))
        assertTrue(body(screens, "private fun AccountRows(").contains("countsDisagreeLine(c)"), "the line about the counts is inside the box")
        val requests = body(screens, "private fun RecoverySection(")
        assertTrue(requests.contains("WithSaidBeside({ SectionTitle(Placeholder.OP_REQUESTS) }) { OperatorSaid(op, OperatorModel.Area.REQUESTS, anyAction = true) }"))
        assertTrue(requests.contains("ListBox(REQUESTS_BOX) { RequestRows("))
        val audit = body(screens, "private fun AuditSection(")
        assertTrue(audit.contains("FixedSlot(AUDIT_FOR_SLOT)"))
        assertTrue(audit.substringAfter("WithSaidBeside({ NarrowSecond(UiText.ph(Placeholder.OP_AUDIT_READ)").substringBefore("ListBox(AUDIT_BOX)").contains("OperatorSaid(op, OperatorModel.Area.AUDIT)"))
        val box = audit.substringAfter("ListBox(AUDIT_BOX) {")
        assertTrue(box.contains("OP_AUDIT_PAGE_FULL") && box.contains("for (row in c.audit)"), "the page-full line and the rows are in the box")
        val policy = body(screens, "private fun PolicySection(").substringAfter("WithSaidBeside({ Quieter(UiText.ph(Placeholder.OP_POLICY_EDIT")
        assertTrue(policy.contains("OperatorSaid(op, OperatorModel.Area.POLICY)") && policy.contains("OperatorSaid(op, OperatorModel.Area.POLICY, null, OperatorModel.Action.POLICY)"))
        // No section keeps an empty slot of its own under a control.
        assertTrue(!screens.contains("FixedSlot(CONSOLE_SAID_SLOT)"))
    }
}
