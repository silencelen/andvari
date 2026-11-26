package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.TextButton
import androidx.compose.ui.text.TextStyle
import io.silencelen.andvari.core.model.wire.AdminPolicy
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.HourglassEmpty
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.foundation.LocalIndication
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.OperatorDeleteWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.model.wire.AccountRole
import io.silencelen.andvari.core.model.wire.AccountStatus
import io.silencelen.andvari.core.model.wire.AccountSummary
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.OperatorConsole
import java.text.DateFormat
import java.util.Date

/**
 * The operator's console (design §9.1, §9.2), a page of the signed-in area that only the operator account has
 * ([OperatorModel.available]; the top bar shows its icon to nobody else). The page opens the console when it is shown
 * and closes it when it is left. While the first read is under way nothing of the server is shown; a refused first
 * read says why, in place, and offers to read again.
 */
@Composable
internal fun OperatorPage(model: TrustModel, s: AppSnapshot) {
    val op = model.operator
    if (!op.available(s)) return
    val console by op.consoles.collectAsState()
    val opening by op.opening.collectAsState()
    op.answers.collectAsState().value
    // Shown: open it (once per visit); left: close it, so the next visit reads the server again.
    LaunchedEffect(Unit) { if (op.consoles.value == null && op.opening.value == OperatorModel.Opening.NOT_ASKED) op.open() }
    DisposableEffect(Unit) { onDispose { op.close() } }
    Say(Placeholder.OPERATOR_CONSOLE, style = MaterialTheme.typography.titleSmall)
    val c = console
    if (c == null) {
        s.instance?.let { InstanceName(it.label, MaterialTheme.typography.bodyLarge) }
        when (opening) {
            OperatorModel.Opening.REFUSED -> {
                Quiet(UiText.ph(Placeholder.OP_NOT_READ))
                OperatorSaid(op, OperatorModel.Area.CONSOLE)
                Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { op.open() }
            }
            else -> Row(verticalAlignment = Alignment.CenterVertically) {
                OpeningSpinner(UiText.ph(Placeholder.OP_READING))
                Say(UiText.ph(Placeholder.OP_READING), Modifier.padding(start = 8.dp))
            }
        }
        return
    }
    // The current app's page of its own: each part of the console a card of the page's width, as Settings' are.
    SectionCard { ConsoleHeader(op, s, c) }
    SectionCard { AccountsSection(op, s, c) }
    SectionCard { RecoverySection(op, s, c) }
    SectionCard { AuditSection(op, s, c) }
    SectionCard { PolicySection(op, s, c) }
    SectionCard { CardSection(op, s, c) }
    // Every action that asks for the master password: its inputs, then its password step, each a dialog of its own
    // whose layout nothing on the page can move (a field that grew once put the password into another field).
    val chosen by op.chosen.collectAsState()
    val step by op.step.collectAsState()
    val open = step
    when {
        // Answering a request keeps both of its steps together.
        open?.action == OperatorModel.Action.FULFIL -> FulfilStep(op, s, open.chosen, open)
        open != null -> PasswordStepDialog(op, s, open)
        chosen?.action == OperatorModel.Action.FULFIL -> FulfilStep(op, s, chosen!!, null)
        else -> chosen?.let { InputStepDialog(op, s, c, it) }
    }
}

/**
 * Text that may be long (a name or an address from the server, a pasted value) on one line of a fixed height: it
 * scrolls sideways, so it never pushes what is below it. Not selectable: a selection was a Tab stop with no visible
 * focus mark, two of them before a step's first control (found in the keyboard walk).
 */
@Composable
internal fun OneLine(text: String, style: TextStyle = MaterialTheme.typography.bodyMedium, mono: Boolean = false, color: Color = Color.Unspecified) {
    Text(
        plainName(text), Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        style = if (mono) style.copy(fontFamily = FontFamily.Monospace) else style, color = color, maxLines = 1, softWrap = false,
    )
}

/** The line a step says (a check refused, a wrong password): in a slot of a fixed height under the step's fields; a long line scrolls inside it. */
@Composable
private fun StepSaid(op: OperatorModel, area: OperatorModel.Area, key: String?, action: OperatorModel.Action) {
    op.answers.collectAsState().value
    val a = op.answerFor(area, key, action)
    Box(Modifier.fillMaxWidth().height(STEP_SAID_HEIGHT).verticalScroll(rememberScrollState())) {
        a?.let {
            Say(it.text, Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite }, MaterialTheme.typography.bodyMedium, MaterialTheme.colorScheme.error)
        }
    }
}

// Three lines: at two, the answer step's longer refusals were cut.
private val STEP_SAID_HEIGHT = 72.dp

// The console's fixed slots and boxes: what a read adds or changes stays inside them.
/**
 * The header's lines a read can add: the status line (always, after a read), then setup unfinished, mail stalled, rows
 * not shown; more than fit scroll inside.
 */
internal val CONSOLE_HEADER_SLOT = 88.dp

/** What a read or an action answered, under its control (two lines, then it scrolls). */
internal val CONSOLE_SAID_SLOT = 48.dp

/** The audit's "for this account" line. */
internal val AUDIT_FOR_SLOT = 44.dp

internal val ACCOUNTS_BOX = 360.dp
internal val REQUESTS_BOX = 360.dp
internal val AUDIT_BOX = 300.dp

/**
 * A control with what its part of the console answered beside it, in a slot of the row's own height (two lines, then it
 * scrolls): an answer that comes moves nothing, and an empty slot leaves no gap under the control (found in the run).
 */
@Composable
private fun WithSaidBeside(control: @Composable () -> Unit, said: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        control()
        Box(Modifier.weight(1f).height(CONSOLE_SAID_SLOT).padding(start = 8.dp).verticalScroll(rememberScrollState()), contentAlignment = Alignment.CenterStart) { said() }
    }
}

/** What a step is for: each value on a line of its own, as it was when the action was chosen. */
@Composable
private fun StepValues(values: List<OperatorModel.StepValue>) {
    for (v in values) {
        Say(v.label, style = MaterialTheme.typography.labelSmall)
        if (v.value.isPlaceholder) Say(v.value) else OneLine(v.value.shown(), mono = true)
    }
}

/**
 * The frame of a step: a dialog with a fixed layout. Cancel is the way out and Escape's; Enter sends from the last field.
 * Its content never changes height while it is open, so the dialog, centred in the window, never moves under the pointer.
 */
@Composable
private fun StepFrame(title: UiText, confirm: UiText, confirmEnabled: Boolean, onCancel: () -> Unit, onConfirm: () -> Unit, content: @Composable () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Say(title, style = MaterialTheme.typography.titleMedium) },
        text = { Column(Modifier.widthIn(min = 320.dp, max = 560.dp).verticalScroll(rememberScrollState())) { content() } },
        dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), onClick = onCancel) },
        confirmButton = { DialogButton(confirm, enabled = confirmEnabled, onClick = onConfirm) },
    )
}

/** What a password step says above its field: what will be done, then to what, as it was when the action was chosen. */
@Composable
private fun StepIntro(step: OperatorModel.Step) {
    for (line in step.lines) Say(line.text, color = if (line.warn) MaterialTheme.colorScheme.error else Color.Unspecified)
    Gap(8)
    StepValues(step.values)
    Quiet(UiText.ph(Placeholder.OP_STEP_AS_CHOSEN))
    Gap(8)
}

/** Send [step] with what was typed, and empty the field: a wrong password is typed again. */
private fun sendStep(op: OperatorModel, s: AppSnapshot, step: OperatorModel.Step, password: String): Boolean {
    if (password.isEmpty() || s.busy) return false
    op.confirm(step, password)
    return true
}

/**
 * The password step of an action: what will be done and to what ([StepIntro]); then the master password (Enter sends
 * it); then, in its fixed slot, what the step said. A wrong password keeps it open. Nothing is focused by itself
 * (§12.1): the dialog's first control is the field's own.
 */
@Composable
private fun PasswordStepDialog(op: OperatorModel, s: AppSnapshot, step: OperatorModel.Step) {
    var password by remember(step) { mutableStateOf("") }
    val send = { if (sendStep(op, s, step, password)) password = "" }
    StepFrame(step.title, step.confirm, password.isNotEmpty() && !s.busy, { op.cancelStep() }, send) {
        StepIntro(step)
        MasterPasswordField(s, password, onEnter = send) { password = it }
        StepSaid(op, step.chosen.area, step.chosen.key, step.action)
    }
}

/** The inputs of an action that has them, entered and checked before its password step opens. */
@Composable
private fun InputStepDialog(op: OperatorModel, s: AppSnapshot, c: OperatorConsole, chosen: OperatorModel.Chosen) {
    val cancel = { op.cancelStep() }
    val next = UiText.ph(Placeholder.OP_STEP_NEXT)
    val said = @Composable { StepSaid(op, chosen.area, chosen.key, chosen.action) }
    when (chosen.action) {
        OperatorModel.Action.DISABLE -> {
            var why by remember(chosen) { mutableStateOf<DisableWhy?>(null) }
            StepFrame(UiText.ph(Placeholder.OP_DISABLE, stepTarget(chosen)), next, why != null && !s.busy, cancel, { why?.let { op.checkDisable(chosen, it) } }) {
                StepValues(chosen.values)
                Quiet(UiText.Plain(OperatorDesignWords.DISABLE))
                Say(Placeholder.OP_DISABLE_WHY, style = MaterialTheme.typography.labelMedium)
                for (w in DisableWhy.entries) Choice(disableWhyLabel(w), UiText.Plain(""), selected = why == w, enabled = !s.busy) { why = w }
                said()
            }
        }
        OperatorModel.Action.QUOTA -> {
            var bytes by remember(chosen) { mutableStateOf("") }
            var items by remember(chosen) { mutableStateOf("") }
            var vaults by remember(chosen) { mutableStateOf("") }
            var links by remember(chosen) { mutableStateOf("") }
            val check = { op.checkQuota(chosen, QuotaTyped(bytes, items, vaults, links)); Unit }
            StepFrame(UiText.ph(Placeholder.OP_QUOTA, stepTarget(chosen)), next, !s.busy, cancel, check) {
                StepValues(chosen.values)
                Quiet(UiText.Plain(OperatorDesignWords.QUOTA))
                quotaDefaultsLine(c)?.let { Quiet(it) }
                Field(UiText.ph(Placeholder.OP_QUOTA_BYTES), bytes, mono = true) { bytes = it }
                Field(UiText.ph(Placeholder.OP_QUOTA_ITEMS), items, mono = true) { items = it }
                Field(UiText.ph(Placeholder.OP_QUOTA_VAULTS), vaults, mono = true) { vaults = it }
                Field(UiText.ph(Placeholder.OP_QUOTA_LINKS), links, mono = true, onEnter = check) { links = it }
                said()
            }
        }
        OperatorModel.Action.DELETE -> DeleteAccountStep(op, s, chosen)
        OperatorModel.Action.POLICY -> c.policy?.let { PolicyInputs(op, s, chosen, it) } ?: LaunchedEffect(chosen) { op.cancelStep() }
        OperatorModel.Action.RENAME -> {
            var name by remember(chosen) { mutableStateOf(c.instance.name) }
            val check = { op.checkRename(chosen, name); Unit }
            StepFrame(UiText.ph(Placeholder.OP_CARD_RENAME, stepTarget(chosen)), next, !s.busy, cancel, check) {
                StepValues(chosen.values)
                Field(UiText.ph(Placeholder.OP_CARD_NAME), name, onEnter = check) { name = it }
                said()
            }
        }
        OperatorModel.Action.MOVE -> {
            var origin by remember(chosen) { mutableStateOf("") }
            val check = { op.checkMove(chosen, origin); Unit }
            StepFrame(UiText.ph(Placeholder.OP_CARD_MOVE, stepTarget(chosen)), next, origin.isNotBlank() && !s.busy, cancel, check) {
                StepValues(chosen.values)
                Quiet(UiText.ph(Placeholder.OP_CARD_MOVE_WHAT))
                Quiet(UiText.Plain(OperatorDesignWords.ADDRESS_STAYS))
                Field(UiText.ph(Placeholder.OP_CARD_ORIGIN), origin, mono = true, onEnter = check) { origin = it }
                said()
            }
        }
        OperatorModel.Action.RECOVERY_SET -> {
            var fingerprint by remember(chosen) { mutableStateOf("") }
            var statement by remember(chosen) { mutableStateOf("") }
            StepFrame(UiText.ph(Placeholder.OP_RECOVERY_SET, stepTarget(chosen)), next, fingerprint.isNotBlank() && !s.busy, cancel, { op.checkRecoverySet(chosen, fingerprint, statement) }) {
                StepValues(chosen.values)
                // Said whatever is typed, so nothing under the fields comes and goes while they are filled.
                Quiet(UiText.ph(Placeholder.OP_ROTATION_UNSIGNED))
                Field(UiText.ph(Placeholder.OP_RECOVERY_FP), fingerprint, mono = true) { fingerprint = it }
                Field(UiText.ph(Placeholder.OP_ROTATION_STATEMENT), statement, mono = true, lines = 2, maxLines = 2) { statement = it }
                said()
            }
        }
        OperatorModel.Action.RECOVERY_REMOVE -> {
            var typed by remember(chosen) { mutableStateOf("") }
            val check = { op.checkRecoveryRemove(chosen, typed); Unit }
            StepFrame(UiText.ph(Placeholder.OP_RECOVERY_REMOVE, stepTarget(chosen)), next, typed.isNotBlank() && !s.busy, cancel, check) {
                StepValues(chosen.values)
                for (line in recoveryRemoveLines(warn = false)) Say(line.text)
                Gap(8)
                Say(Placeholder.OP_REMOVE_TYPE, style = MaterialTheme.typography.labelMedium)
                Field(UiText.ph(Placeholder.OP_STEP_SERVER_ADDRESS), typed, mono = true, onEnter = check) { typed = it }
                said()
            }
        }
        // Chosen without inputs: their password step opened at once.
        else -> LaunchedEffect(chosen) { op.cancelStep() }
    }
}

/** The instance's default quotas, when the policy was read: shown beside an account's quota fields. */
internal fun quotaDefaultsLine(c: OperatorConsole): UiText? = c.policy?.quotaDefaults?.let { d ->
    UiText.ph(Placeholder.OP_QUOTA_DEFAULTS, d.accountBytes.toString() + " (" + sizeText(d.accountBytes) + ")", d.items.toString(), d.ownedSharedVaults.toString(), d.openLinks.toString())
}

/** A control that chooses an action, with that action's own answer said beside it. */
@Composable
private fun ActionControl(
    op: OperatorModel, s: AppSnapshot, label: UiText, area: OperatorModel.Area, key: String?, action: OperatorModel.Action,
    about: String? = null, quiet: Boolean = false, choose: () -> Unit,
) {
    if (quiet) Quieter(label, enabled = !s.busy) { choose() } else Second(label, enabled = !s.busy) { choose() }
    OperatorSaid(op, area, key, action, about)
}

/**
 * Sentences the design itself gives for the operator's views (design 2026-11-15-onboarding-trust.md), quoted exactly
 * and shown as plain text. Each names its place in the design; the owner reviews them with the placeholders.
 */
internal object OperatorDesignWords {
    /** §9.2, the disable route. */
    const val DISABLE = "Revokes sessions and emails the person."

    /** §9.2, the enable route. */
    const val ENABLE = "Re-enables the account and emails the person."

    /** §9.2, the quota route. */
    const val QUOTA = "Per-account overrides."

    /** §9.2, the delete route: the 30-day rule (working assumption W2), quoted without its references. */
    const val DELETE_RULE = "Only for accounts disabled at least 30 days."

    /** §9.2, the delete route. */
    const val DELETE_BLOCKED = "Refused while the account owns a shared vault with other members."

    /** §9.2, the escrow route. */
    const val ESCROW = "Emails the person \"the operator downloaded your recovery copy\"."

    /** §9.3 step 3: what the operator does before an answer exists (the code marks left out). */
    val FULFIL_OPERATOR = listOf(
        "The operator contacts the person through a channel they trust independently of the server and the inbox.",
        "They ask for the request code, and if possible the account ID.",
        "The panel and andvari-cli operator never display the request code.",
        "The server refuses before the hold has passed or after a veto.",
    )

    /** §9.3 steps 4 and 5, their opening sentences: what follows for the person. */
    val FULFIL_PERSON = listOf(
        "The app picks it up.",
        "Then the person checks the account, before any new password is set.",
        "The person sets a new password.",
    )

    /** §9.3 step 1, lifetimes (FI-R9): how a request ends without anyone acting, up to the clause about the app. */
    const val REQUEST_ENDS = "A verified request lives until commit or veto, or until 30 days after its hold ended, when it expires."

    /** §4.4, after a move (R36): the warning the self-hosting guide repeats, the design's emphasis left out. */
    const val ADDRESS_STAYS = "An address the chain has ever named must stay the operator's."

    /** §7.1, the panel's sign-up controls (the design's emphasis and code marks left out). */
    const val SIGNUP_TIGHTEN = "The operator panel can only tighten: close sign-up, move open to links, or lower the cap."
}

/**
 * The accounts, as the server lists them: what each row carries and nothing else (spec 03 §7.1's `AccountSummary`; it
 * carries no quota, so usage is shown as used, and the instance's defaults sit beside the quota fields). A line says
 * when the server's own count and its list disagree. Each row opens its actions in place.
 */
@Composable
private fun AccountsSection(op: OperatorModel, s: AppSnapshot, c: OperatorConsole) {
    var open by remember { mutableStateOf<String?>(null) }
    SectionTitle(Placeholder.OP_ACCOUNTS)
    // The list in a box of a fixed height: a read that adds or drops rows moves nothing below it.
    ListBox(ACCOUNTS_BOX) { AccountRows(op, s, c, open) { open = it } }
}

@Composable
private fun AccountRows(op: OperatorModel, s: AppSnapshot, c: OperatorConsole, open: String?, setOpen: (String?) -> Unit) {
    countsDisagreeLine(c)?.let { Say(it, color = MaterialTheme.colorScheme.error) }
    for (a in c.accounts) {
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (a.status == AccountStatus.DISABLED) {
                    Icon(Icons.Default.Block, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.error)
                    Say(UiText.ph(Placeholder.OP_STATUS_DISABLED), Modifier.padding(start = 4.dp, end = 8.dp), MaterialTheme.typography.labelSmall)
                }
                OneLine(a.email, MaterialTheme.typography.bodyLarge)
            }
            if (a.displayName.isNotEmpty()) OneLine(a.displayName, MaterialTheme.typography.bodySmall)
            if (a.role == AccountRole.OPERATOR) Quiet(UiText.ph(Placeholder.OP_ROLE_OPERATOR))
            Quiet(
                UiText.ph(
                    Placeholder.OP_ACCOUNT_ROW,
                    opDate(a.createdAt),
                    a.lastSeenAt?.let { opDate(it) } ?: UiText.ph(Placeholder.OP_NEVER).shown(),
                    a.recovery,
                    sizeText(a.usedBytes),
                    a.itemCount.toString(),
                    a.ownedVaultCount.toString(),
                    a.liveDeviceCount.toString(),
                ),
            )
            a.disabledAt?.let { Quiet(UiText.ph(Placeholder.OP_DISABLED_SINCE, opDate(it))) }
            if (open == a.userId) {
                AccountPanel(op, s, c, a) { setOpen(null) }
            } else {
                Quieter(UiText.ph(Placeholder.OP_MANAGE, plainName(a.email)), enabled = !s.busy) { setOpen(a.userId) }
                OperatorSaid(op, OperatorModel.Area.ACCOUNT, a.userId)
            }
        }
    }
}

/**
 * One account's actions: disable for a closed reason, or enable; its quota; its devices; its recovery copy; its audit;
 * deleting it. Each action is chosen here and its inputs and master password are taken in a step of its own
 * ([InputStepDialog], [PasswordStepDialog]); what it came to is said beside its control. Not offered on the operator's
 * own row where the server refuses.
 */
@Composable
private fun AccountPanel(op: OperatorModel, s: AppSnapshot, c: OperatorConsole, a: AccountSummary, close: () -> Unit) {
    val area = OperatorModel.Area.ACCOUNT
    // Every control names its target, drawn plainly.
    val email = plainName(a.email)
    // In the list, as the current app draws a vault's settings in its Sharing page: a card of its own under the row.
    PanelCard {
        // What only reads or changes a limit first; disabling and deleting after them, so the focus never reaches a
        // destructive action first when the panel opens (the keyboard walk).
        Quiet(UiText.Plain(OperatorDesignWords.QUOTA))
        ActionControl(op, s, UiText.ph(Placeholder.OP_QUOTA, email), area, a.userId, OperatorModel.Action.QUOTA) { op.chooseFor(OperatorModel.Action.QUOTA, a) }
        AccountDevices(op, s, c, a)
        // The recovery copy exists only for an account that chose operator recovery (the server's record of it).
        if (a.recovery == "operator") EscrowControls(op, s, a)
        Quieter(UiText.ph(Placeholder.OP_AUDIT_OF, email), enabled = !s.busy) { op.loadAudit(auditSince(c, AuditSince.MONTH), null, a.userId) }
        if (a.role != AccountRole.OPERATOR) {
            if (a.status == AccountStatus.DISABLED) {
                Quiet(UiText.Plain(OperatorDesignWords.ENABLE))
                ActionControl(op, s, UiText.ph(Placeholder.OP_ENABLE, email), area, a.userId, OperatorModel.Action.ENABLE) { op.chooseFor(OperatorModel.Action.ENABLE, a) }
                // A disable that was done turned its control into this one: its line is said here (found in the run).
                OperatorSaid(op, area, a.userId, OperatorModel.Action.DISABLE)
            } else {
                Quiet(UiText.Plain(OperatorDesignWords.DISABLE))
                ActionControl(op, s, UiText.ph(Placeholder.OP_DISABLE, email), area, a.userId, OperatorModel.Action.DISABLE) { op.chooseFor(OperatorModel.Action.DISABLE, a) }
                OperatorSaid(op, area, a.userId, OperatorModel.Action.ENABLE)
            }
        }
        // Only a disabled account can be deleted, and never the operator's own (the server refuses both).
        if (a.role != AccountRole.OPERATOR && a.status == AccountStatus.DISABLED) {
            ActionControl(op, s, UiText.ph(Placeholder.OP_DELETE, email), area, a.userId, OperatorModel.Action.DELETE) { op.chooseFor(OperatorModel.Action.DELETE, a) }
        }
        OperatorSaid(op, area, a.userId)
        Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { close() }
    }
}

/**
 * Deleting an account as the operator (§9.2; spec 03 §7.1), its inputs: the rule, what deletion does, and the reason, as
 * a choice between the two fixed reasons and never typed. Its password step then says what the server will record,
 * and that the record outlives the account, before the master password ([OperatorModel.checkDelete]).
 */
@Composable
private fun DeleteAccountStep(op: OperatorModel, s: AppSnapshot, chosen: OperatorModel.Chosen) {
    var why by remember(chosen) { mutableStateOf<OperatorDeleteWhy?>(null) }
    StepFrame(UiText.ph(Placeholder.OP_DELETE, stepTarget(chosen)), UiText.ph(Placeholder.OP_STEP_NEXT), why != null && !s.busy, { op.cancelStep() }, { why?.let { op.checkDelete(chosen, it) } }) {
        StepValues(chosen.values)
        Say(UiText.Plain(OperatorDesignWords.DELETE_RULE))
        Quiet(UiText.Plain(OperatorDesignWords.DELETE_BLOCKED))
        Quiet(UiText.ph(Placeholder.OP_DELETE_WHAT))
        Say(Placeholder.OP_DELETE_WHY, style = MaterialTheme.typography.labelMedium)
        for (w in OperatorDeleteWhy.entries) {
            Choice(deleteWhyLabel(w), deleteWhyDetail(w), selected = why == w, enabled = !s.busy) { why = w }
        }
        StepSaid(op, chosen.area, chosen.key, chosen.action)
    }
}

/** The two fixed reasons for an operator's deletion ([OperatorDeleteWhy]): offered as a choice, never typed. */
internal fun deleteWhyLabel(w: OperatorDeleteWhy): UiText = UiText.ph(
    when (w) {
        OperatorDeleteWhy.DISABLED_30_DAYS -> Placeholder.OP_DELETE_WHY_30_DAYS
        OperatorDeleteWhy.UNDER_MINIMUM_AGE -> Placeholder.OP_DELETE_WHY_UNDER_AGE
    },
)

internal fun deleteWhyDetail(w: OperatorDeleteWhy): UiText = when (w) {
    // The rule is said once, above the choice (it showed twice in the run).
    OperatorDeleteWhy.DISABLED_30_DAYS -> UiText.Plain("")
    OperatorDeleteWhy.UNDER_MINIMUM_AGE -> UiText.ph(Placeholder.OP_DELETE_UNDER_AGE_DETAIL)
}

/**
 * What the server records of the deletion (spec 03 §7.1): the operator's own audit row, with a pseudonym for the
 * account and, for the minimum age, the reason; kept for the ordinary retention after the account is gone.
 */
internal fun deleteRecordLine(w: OperatorDeleteWhy): UiText = UiText.ph(
    when (w) {
        OperatorDeleteWhy.DISABLED_30_DAYS -> Placeholder.OP_DELETE_RECORD
        OperatorDeleteWhy.UNDER_MINIMUM_AGE -> Placeholder.OP_DELETE_RECORD_UNDER_AGE
    },
)

/**
 * An account's devices, read in pages by core: nothing shows until the last page arrived. Each device on show can be
 * revoked with the master password; the person is emailed.
 */
@Composable
private fun AccountDevices(op: OperatorModel, s: AppSnapshot, c: OperatorConsole, a: AccountSummary) {
    val asked by op.devicesAsked.collectAsState()
    if (asked != a.userId) {
        Quieter(UiText.ph(Placeholder.OP_DEVICES_OF, plainName(a.email)), enabled = !s.busy) { op.openDevices(a.userId) }
        return
    }
    Say(UiText.ph(Placeholder.OP_DEVICES_OF, plainName(a.email)), style = MaterialTheme.typography.labelMedium)
    val devices = op.devicesShown(c, a.userId)
    if (devices == null) {
        // Under way, or refused: nothing of a part-read list is shown.
        if (op.answerAt(OperatorModel.Area.DEVICES, a.userId) == null) Quiet(UiText.ph(Placeholder.OP_DEVICES_READING))
    } else {
        if (devices.isEmpty()) Quiet(UiText.ph(Placeholder.OP_NO_DEVICES))
        for (d in devices) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (!d.live) Icon(Icons.Default.Block, null, Modifier.size(14.dp).padding(end = 2.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                OneLine(d.name + "  ·  " + d.platform)
            }
            Quiet(
                UiText.ph(
                    if (d.live) Placeholder.OP_DEVICE_LIVE else Placeholder.OP_DEVICE_NOT_LIVE,
                    opDate(d.createdAt),
                    d.lastSeenAt?.let { opDate(it) } ?: UiText.ph(Placeholder.OP_NEVER).shown(),
                    d.clientVersion ?: UiText.ph(Placeholder.OP_NOT_GIVEN).shown(),
                    d.how + (d.linkedFrom?.let { " ($it)" } ?: ""),
                ),
            )
            ActionControl(op, s, UiText.ph(Placeholder.OP_REVOKE_DEVICE, plainName(d.name)), OperatorModel.Area.DEVICES, a.userId, OperatorModel.Action.REVOKE, d.deviceId, quiet = true) {
                op.chooseFor(OperatorModel.Action.REVOKE, a, d)
            }
        }
    }
    OperatorSaid(op, OperatorModel.Area.DEVICES, a.userId)
    Quieter(UiText.ph(Placeholder.OP_DEVICES_CLOSE), enabled = !s.busy) { op.closeDevices() }
}

/**
 * An account's recovery copy (§9.2, †): downloaded with the master password, then saved once to a file for
 * `recovery-cli` on an offline machine. The file dialog comes first, so a cancelled dialog takes nothing; asked a second
 * time, the screen says the copy was handed over already.
 */
/**
 * What saving the recovery copy said. It is handed over once (taken from this computer, its bytes zeroed after the
 * write), so a save that failed cannot be tried at another place: a new download is the way, and it emails the person
 * again. Where only the last step failed, the checked copy was left beside the place, under the name given.
 */
internal fun escrowWrittenLine(written: FileWritten, email: String, path: String): UiText = when {
    written.result == ExportWrite.SAVED -> UiText.ph(Placeholder.OP_ESCROW_SAVED, email, path)
    written.keptAs != null -> UiText.ph(Placeholder.FILE_KEPT_ASIDE, written.keptAs)
    else -> UiText.ph(Placeholder.OP_ESCROW_NOT_SAVED)
}

@Composable
private fun EscrowControls(op: OperatorModel, s: AppSnapshot, a: AccountSummary) {
    val waiting by op.escrowFor.collectAsState()
    val work = rememberWorkScope()
    val overwrite = remember(a.userId) { OverwriteGate() }
    val escrow = OperatorModel.Action.ESCROW
    val email = plainName(a.email)
    Say(Placeholder.OP_ESCROW, style = MaterialTheme.typography.labelMedium)
    Quiet(UiText.Plain(OperatorDesignWords.ESCROW))
    ActionControl(op, s, UiText.ph(Placeholder.OP_ESCROW_DOWNLOAD, email), OperatorModel.Area.ACCOUNT, a.userId, escrow) { op.chooseFor(escrow, a) }
    if (waiting == a.userId) {
        Second(UiText.ph(Placeholder.OP_ESCROW_SAVE, email), enabled = !s.busy) {
            // Named for whose it is; a file already there is replaced only when asked.
            when (val pick = FilePicker.save(UiText.ph(Placeholder.OP_ESCROW_SAVE, email).shown(), escrowFileName(a.email))) {
                is FilePicker.SavePick.At -> overwrite.request(pick.file) {
                    val bytes = op.takeEscrowFile(a.userId) ?: return@request
                    work.launch {
                        val written = withContext(Dispatchers.IO) { writeVerified(pick.file, bytes) }
                        bytes.fill(0)
                        val line = escrowWrittenLine(written, email, pick.file.absolutePath)
                        op.sayAt(OperatorModel.Area.ACCOUNT, a.userId, line, escrow)
                    }
                }
                FilePicker.SavePick.Outside -> op.sayAt(OperatorModel.Area.ACCOUNT, a.userId, UiText.ph(Placeholder.ATTACHMENT_NOT_WRITTEN), escrow)
                FilePicker.SavePick.Cancelled -> {}
            }
        }
    }
    ReplaceFileDialog(overwrite)
}

/** The recovery copy's file name: whose it is, in the characters a file name takes everywhere. */
internal fun escrowFileName(email: String): String =
    "recovery-copy-" + email.lowercase().map { if (it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' || it == '@') it else '_' }.joinToString("").take(80) + ".json"

/**
 * A name or an address from the server, drawn plainly: a character that acts on the layout
 * (a direction override or isolate, a zero-width or other format character, a line or paragraph separator, a control
 * character) is shown escaped as ⟨U+XXXX⟩, never obeyed.
 */
internal fun plainName(text: String): String {
    val out = StringBuilder(text.length)
    var i = 0
    while (i < text.length) {
        val cp = text.codePointAt(i)
        val t = Character.getType(cp)
        val acts = t == Character.CONTROL.toInt() || t == Character.FORMAT.toInt() || t == Character.LINE_SEPARATOR.toInt() ||
            t == Character.PARAGRAPH_SEPARATOR.toInt() || t == Character.SURROGATE.toInt() || t == Character.PRIVATE_USE.toInt()
        if (acts) out.append("⟨U+").append(Integer.toHexString(cp).uppercase().padStart(4, '0')).append('⟩') else out.appendCodePoint(cp)
        i += Character.charCount(cp)
    }
    return out.toString()
}

/**
 * Requests for the operator's help (§9.3), as the server lists them: never the request code, which the operator gets
 * from the person and types into `recovery-cli assist`. Each shows the address the server says it was made for (and that
 * the tool asks for the person's address from the operator's own knowledge), whether it was answered, and the request's
 * id and key with a copy control each; never the server's account ID. It takes the answer the tool produced, again until
 * the person has finished (a newer upload replaces the older). There is no "refuse": only the person's own devices can
 * cancel a request, and one left alone ends by itself.
 */
@Composable
private fun RecoverySection(op: OperatorModel, s: AppSnapshot, c: OperatorConsole) {
    // What is said about a request the list no longer holds, beside the section's title: no empty slot under it.
    WithSaidBeside({ SectionTitle(Placeholder.OP_REQUESTS) }) { OperatorSaid(op, OperatorModel.Area.REQUESTS, anyAction = true) }
    // What fulfilling means, for the operator and for the person, in the design's words: always on show, above the box,
    // so the box holds only the requests (the run found the rows below the fold of their own box).
    Say(Placeholder.OP_FULFIL_FOR_OPERATOR, style = MaterialTheme.typography.labelMedium)
    for (line in OperatorDesignWords.FULFIL_OPERATOR) Quiet(UiText.Plain(line))
    Say(Placeholder.OP_FULFIL_FOR_PERSON, style = MaterialTheme.typography.labelMedium)
    for (line in OperatorDesignWords.FULFIL_PERSON) Quiet(UiText.Plain(line))
    // What the operator can do instead of refusing: nothing; the request ends by itself.
    Quiet(UiText.ph(Placeholder.OP_NO_REFUSE))
    Quiet(UiText.Plain(OperatorDesignWords.REQUEST_ENDS))
    // The requests in a box of a fixed height: a read that adds, answers or drops one moves nothing below it.
    ListBox(REQUESTS_BOX) { RequestRows(op, s, c) }
}

@Composable
private fun RequestRows(op: OperatorModel, s: AppSnapshot, c: OperatorConsole) {
    if (c.recoveryRequests.isEmpty()) {
        Quiet(UiText.ph(Placeholder.OP_NO_REQUESTS))
        return
    }
    val now = c.status?.serverTime
    for (r in c.recoveryRequests) {
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                val holding = now != null && now < r.holdEndsAt
                // The space goes outside the mark: padding inside a 14 dp size left a 12 dp hourglass that read as a box.
                if (holding) Icon(Icons.Default.HourglassEmpty, null, Modifier.padding(end = 4.dp).size(18.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                OneLine(r.email, MaterialTheme.typography.bodyLarge)
            }
            // The address is the server's word; the offline tool takes the person's address from the operator.
            Quiet(UiText.ph(Placeholder.OP_REQUEST_ADDRESS_SAID))
            // Answered or not, from the closed list of states only.
            val state = requestState(r)
            Say(state.words, style = MaterialTheme.typography.labelMedium)
            // A copy sealed to the recovery key before it changed: both sheets are needed (the shared code's line).
            c.outgoingKeyLine(r)?.let { Say(it, color = MaterialTheme.colorScheme.error) }
            // The platform from the closed list only: anything else the server says is not drawn.
            val platform = r.platform.takeIf { io.silencelen.andvari.core.trust.TrustGrammar.isPlatform(it) } ?: UiText.ph(Placeholder.OP_NOT_GIVEN).shown()
            Quiet(UiText.ph(Placeholder.OP_REQUEST_ROW, opDate(r.createdAt), opDate(r.verifiedAt), opDate(r.holdEndsAt), platform))
            Quiet(UiText.ph(Placeholder.OP_REQUEST_IDS))
            Quiet(UiText.ph(Placeholder.OP_IDS_HOW_SHOWN))
            // Only what the offline tool needs of the request itself: its id and its key (a swapped key is caught by the
            // code the person reads out). The server's account ID is never offered as a value to copy or check against:
            // whatever an account is checked against comes from the person, never from the server.
            // Each value grouped by four with its digits marked (a lowercase l was read as a 1 in the first run), and a
            // copy control that copies it whole, without the spaces; recovery-cli refuses a value with spaces in it.
            for ((what, value) in requestValues(r)) {
                CopyableValue(op, r.requestId, what, value)
            }
            FulfilControl(op, s, r.requestId, r.email, again = state == RequestState.ANSWERED)
        }
    }
}

/**
 * A value the operator types or copies into `recovery-cli assist`: shown by [groupedValue] (groups of four; every digit
 * bold, underlined and in the accent colour, so a 1 is not taken for an l nor a 0 for an O, also without colour), and a
 * copy control beside it that copies the value exactly as the server holds it.
 */
@Composable
private fun CopyableValue(op: OperatorModel, requestId: String, what: String, value: String) {
    val clipboard = LocalClipboardManager.current
    val digit = MaterialTheme.colorScheme.primary
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            groupedValue(value, digit), Modifier.weight(1f).semantics { contentDescription = "$what: $value" },
            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
        Quieter(UiText.ph(Placeholder.OP_COPY, what)) {
            clipboard.setText(AnnotatedString(value))
            op.sayAt(OperatorModel.Area.REQUESTS, requestId, UiText.ph(Placeholder.OP_COPIED, what))
        }
    }
}

/** The values of a request the console offers to copy into `recovery-cli assist`: the request's id and its key, nothing of the account. */
internal fun requestValues(r: io.silencelen.andvari.core.model.wire.AdminRecoveryRequest): List<Pair<String, String>> =
    listOf("request" to r.requestId, "request key" to r.rPub)

/** [value] in groups of four (a uuid keeps its own dashes instead), each digit bold, underlined and in [digit]. */
internal fun groupedValue(value: String, digit: Color): AnnotatedString = buildAnnotatedString {
    val groups = if (UUID_SHAPE.matches(value)) listOf(value) else value.chunked(4)
    groups.forEachIndexed { i, g ->
        if (i > 0) append(' ')
        for (c in g) {
            if (c in '0'..'9') withStyle(SpanStyle(color = digit, fontWeight = FontWeight.Bold, textDecoration = TextDecoration.Underline)) { append(c) } else append(c)
        }
    }
}

private val UUID_SHAPE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

/** Answering a request: chosen here; its answer and then its master password are taken in steps of their own ([FulfilStep]). */
@Composable
private fun FulfilControl(op: OperatorModel, s: AppSnapshot, requestId: String, email: String, again: Boolean) {
    val label = UiText.ph(if (again) Placeholder.OP_FULFIL_AGAIN else Placeholder.OP_FULFIL, plainName(email))
    ActionControl(op, s, label, OperatorModel.Area.REQUESTS, requestId, OperatorModel.Action.FULFIL, quiet = true) {
        op.chooseFulfil(requestId)
    }
    // A copied value is said here too.
    OperatorSaid(op, OperatorModel.Area.REQUESTS, requestId)
}

/**
 * The answer `recovery-cli assist` produced, in two steps, each a dialog of a fixed layout. First the answer, pasted or
 * read from its file, in a field of a fixed height, checked on this computer ([OperatorModel.checkAnswer]): the tool's
 * whole output or the answer alone, of an answer's exact size, and when the output names a request, this one. Only an
 * answer that passes opens the password step ([ok]), with the answer no longer editable: in the run, a pasted answer
 * grew its field and moved the password field down, and the password typed where that field had been went into the
 * answer.
 */
@Composable
private fun FulfilStep(op: OperatorModel, s: AppSnapshot, chosen: OperatorModel.Chosen, ok: OperatorModel.Step?) {
    val requestId = chosen.key ?: return
    val fulfil = OperatorModel.Action.FULFIL
    var answer by remember(chosen) { mutableStateOf("") }
    if (ok == null) {
        val check = { op.checkAnswer(requestId, answer)?.let { op.fulfilStep(chosen, answer, it) }; Unit }
        StepFrame(UiText.ph(Placeholder.OP_FULFIL, stepTarget(chosen)), UiText.ph(Placeholder.OP_FULFIL_CHECK), !s.busy, { op.cancelStep() }, check) {
            StepValues(chosen.values)
            Quiet(UiText.ph(Placeholder.OP_REQUEST_ADDRESS_SAID))
            Field(UiText.ph(Placeholder.OP_FULFIL_ANSWER), answer, mono = true, lines = 3, maxLines = 3) { answer = it }
            Quieter(UiText.ph(Placeholder.OP_FULFIL_FROM_FILE), enabled = !s.busy) {
                FilePicker.open(UiText.ph(Placeholder.OP_FULFIL_FROM_FILE).shown())?.let { f ->
                    when (val read = PickedFiles.read(f, 64 * 1024L)) {
                        // Read strictly by the shared reader's file function, and never put on screen: the field stays
                        // empty, and an answer that passes goes straight to the password step.
                        is PickedFiles.Picked.Read -> {
                            answer = ""
                            op.checkAnswerFile(requestId, read.bytes)?.let { op.fulfilStep(chosen, it.sealed, it, fromFile = true) }
                        }
                        // The field shows what the line is about: a file that was not read leaves no earlier answer on show.
                        is PickedFiles.Picked.TooLarge -> { answer = ""; op.sayAt(OperatorModel.Area.REQUESTS, requestId, UiText.ph(Placeholder.OP_ANSWER_TOO_LONG), fulfil) }
                        else -> { answer = ""; op.sayAt(OperatorModel.Area.REQUESTS, requestId, UiText.ph(Placeholder.ATTACHMENT_NOT_READ), fulfil) }
                    }
                }
            }
            StepSaid(op, chosen.area, chosen.key, fulfil)
        }
    } else {
        var password by remember(ok) { mutableStateOf("") }
        val send = { if (sendStep(op, s, ok, password)) password = "" }
        StepFrame(ok.title, ok.confirm, password.isNotEmpty() && !s.busy, { op.cancelStep() }, send) {
            StepIntro(ok)
            MasterPasswordField(s, password, onEnter = send) { password = it }
            StepSaid(op, chosen.area, chosen.key, fulfil)
        }
    }
}

/**
 * The server's identity card (§4.1 to §4.5): its name, its address and its recovery key, each changed by a new card
 * this account's key signs, with the master password (named for the account, the server and its address, §4.4). A
 * wrong password is said and nothing is sent. Handing the server to another operator stays with the command-line tool.
 */
@Composable
private fun CardSection(op: OperatorModel, s: AppSnapshot, c: OperatorConsole) {
    var open by remember { mutableStateOf(false) }
    SectionTitle(Placeholder.OP_CARD)
    InstanceName(c.instance, MaterialTheme.typography.bodyLarge)
    Say(Placeholder.OPERATOR_KEY, style = MaterialTheme.typography.labelSmall)
    Text(c.details.operatorKeyShort.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
    Text("#${c.details.cardSeq}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    PinnedCard0Hash(c.details)
    // The instance id recovery-cli assist and rotate need, and the recovery key the pinned card names: from this
    // computer's pin, never from the server's answer.
    for (v in pinnedCardValues(c.pinnedRecoveryFp, c.pinnedInstanceId, c.status?.instanceKind == "public")) {
        Say(v.label, style = MaterialTheme.typography.labelSmall)
        if (v.value.isPlaceholder) Quiet(v.value) else OneLine(v.value.shown(), MaterialTheme.typography.bodySmall, mono = true)
    }
    Quiet(UiText.ph(Placeholder.OP_HANDOVER_CLI))
    // The server says it stored a new card and does not show it yet: said as that, never as done, and no other
    // card change is offered until it shows.
    if (!cardChangeOffered(c.cardStoredNotShown)) {
        Say(keyLine(CopyKey.OPERATOR_CARD_STORED_NOT_SHOWN), color = MaterialTheme.colorScheme.error)
        OperatorSaid(op, OperatorModel.Area.CARD, anyAction = true)
        return
    }
    if (!open) {
        Quieter(UiText.ph(Placeholder.OP_CARD_CHANGE), enabled = !s.busy) { open = true }
        return
    }
    val card = OperatorModel.Area.CARD
    val server = plainName(c.instance.name)
    ActionControl(op, s, UiText.ph(Placeholder.OP_CARD_RENAME, server), card, OperatorModel.CARD_RENAME, OperatorModel.Action.RENAME) { op.chooseForServer(OperatorModel.Action.RENAME) }
    ActionControl(op, s, UiText.ph(Placeholder.OP_CARD_MOVE, server), card, OperatorModel.CARD_MOVE, OperatorModel.Action.MOVE) { op.chooseForServer(OperatorModel.Action.MOVE) }
    // Under variant R a public server names no recovery key (§7.7): not offered there.
    if (c.status?.instanceKind != "public") {
        Say(Placeholder.OP_RECOVERY_KEY, style = MaterialTheme.typography.labelMedium)
        ActionControl(op, s, UiText.ph(Placeholder.OP_RECOVERY_SET, server), card, OperatorModel.CARD_RECOVERY, OperatorModel.Action.RECOVERY_SET) { op.chooseForServer(OperatorModel.Action.RECOVERY_SET) }
        Gap(16)
        // Its own step, with its own password and a typed confirmation.
        ActionControl(op, s, UiText.ph(Placeholder.OP_RECOVERY_REMOVE, server), card, OperatorModel.CARD_RECOVERY, OperatorModel.Action.RECOVERY_REMOVE) { op.chooseForServer(OperatorModel.Action.RECOVERY_REMOVE) }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { open = false }
}

/** How far back the audit list reads: a day, a week, 30 days, or everything the server keeps. */
internal enum class AuditSince(val days: Int?, val label: Placeholder) {
    DAY(1, Placeholder.OP_AUDIT_DAY), WEEK(7, Placeholder.OP_AUDIT_WEEK), MONTH(30, Placeholder.OP_AUDIT_MONTH), ALL(null, Placeholder.OP_AUDIT_ALL)
}

/** The start of [since], on the server's own clock as its status gave it (the audit's times are the server's), else this computer's. */
internal fun auditSince(c: OperatorConsole, since: AuditSince): Long {
    val days = since.days ?: return 0L
    val now = c.status?.serverTime ?: System.currentTimeMillis()
    return (now - days * 86_400_000L).coerceAtLeast(0L)
}

/** The rows one answer of `GET /admin/audit` holds at most (the server's `OperatorRules.AUDIT_PAGE`; spec 03 §7.3). */
internal const val AUDIT_PAGE_ROWS = 500

/** A page of [rows] is full: older rows that match the filters exist and were not sent. */
internal fun auditPageFull(rows: Int): Boolean = rows >= AUDIT_PAGE_ROWS

/**
 * An audit row's kind as the console says it: the kinds that have words of their own (a refresh the server answered
 * inside its sixty-second grace, `refresh_grace`), and every other kind as the server sent it, made one plain line.
 */
internal fun auditKindLine(type: String): UiText = when (type) {
    "refresh_grace" -> UiText.ph(Placeholder.OP_AUDIT_REFRESH_GRACE)
    else -> UiText.Plain(plainName(type))
}

/** The audit's type filter: a menu of the types the server has sent ([types]), with "every type" first; nothing is typed. */
@Composable
private fun AuditTypeChooser(types: List<String>, chosen: String?, enabled: Boolean, choose: (String?) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        Quieter(UiText.ph(Placeholder.OP_AUDIT_TYPE, chosen ?: UiText.ph(Placeholder.OP_AUDIT_ANY_TYPE).shown()), enabled = enabled) { open = true }
        DropdownMenu(open, onDismissRequest = { open = false }) {
            DropdownMenuItem(text = { Say(Placeholder.OP_AUDIT_ANY_TYPE) }, onClick = { choose(null); open = false })
            // Each kind as served (an unknown one too), made one plain line as a row's kind is.
            for (t in types) DropdownMenuItem(text = { Text(auditKindLine(t).shown(), fontFamily = FontFamily.Monospace) }, onClick = { choose(t); open = false })
        }
    }
}

/**
 * The audit list (§9.4, spec 03 §7.3): ids only, never an email (an account the console lists is named beside its id).
 * Its filters (how far back, a type, one account) are sent to the server, which answers with its newest rows that match,
 * one page of [AUDIT_PAGE_ROWS]; a full page is said, since older rows then exist.
 */
@Composable
private fun AuditSection(op: OperatorModel, s: AppSnapshot, c: OperatorConsole) {
    val filter by op.auditFilter.collectAsState()
    var since by remember { mutableStateOf(AuditSince.WEEK) }
    var type by remember { mutableStateOf<String?>(null) }
    val types by op.auditTypes.collectAsState()
    SectionTitle(Placeholder.OP_AUDIT)
    Actions {
        for (v in AuditSince.entries) {
            val (source, mark) = focusMark(UiText.ph(v.label).shown(), MaterialTheme.shapes.small)
            Row(
                Modifier.then(mark).selectable(since == v, source, LocalIndication.current, enabled = !s.busy, role = Role.RadioButton) { since = v }.padding(end = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(since == v, onClick = null, enabled = !s.busy)
                Say(UiText.ph(v.label), Modifier.padding(start = 4.dp))
            }
        }
    }
    // The type is chosen from those the server has sent, never typed.
    AuditTypeChooser(types, type, !s.busy) { type = it }
    val forAccount = filter?.userId
    // The account the list was read for, in a slot of a fixed height: it comes with a read and moves nothing.
    FixedSlot(AUDIT_FOR_SLOT) {
        if (forAccount != null) {
            val email = c.accounts.firstOrNull { it.userId == forAccount }?.email ?: forAccount
            Row(verticalAlignment = Alignment.CenterVertically) {
                Say(UiText.ph(Placeholder.OP_AUDIT_FOR, plainName(email)))
                Quieter(UiText.ph(Placeholder.OP_AUDIT_ANY_ACCOUNT), enabled = !s.busy) { op.loadAudit(auditSince(c, since), type, null) }
            }
        }
    }
    Quiet(UiText.ph(Placeholder.OP_AUDIT_FILTERED_HERE))
    // "Read" with what the read answered beside it: no empty slot under it.
    WithSaidBeside({ NarrowSecond(UiText.ph(Placeholder.OP_AUDIT_READ), enabled = !s.busy) { op.loadAudit(auditSince(c, since), type, forAccount) } }) {
        OperatorSaid(op, OperatorModel.Area.AUDIT)
    }
    // The rows in a box of a fixed height, there before the first read too: a read that lands moves nothing below.
    ListBox(AUDIT_BOX) {
        if (filter != null) {
            if (c.audit.isEmpty()) Quiet(UiText.ph(Placeholder.OP_AUDIT_EMPTY))
            // The server answers one page of the newest rows; a full page means older ones exist.
            if (auditPageFull(c.audit.size)) Say(UiText.ph(Placeholder.OP_AUDIT_PAGE_FULL), color = MaterialTheme.colorScheme.error)
            for (row in c.audit) {
                Text(opDate(row.at) + "  ·  " + auditKindLine(row.type).shown(), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
                val who = row.userId?.let { id -> c.accounts.firstOrNull { it.userId == id }?.email?.let { "$it ($id)" } ?: id }
                val parts = listOfNotNull(who, row.deviceId, row.ip, row.meta)
                if (parts.isNotEmpty()) Text(plainName(parts.joinToString("  ·  ")), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/** An outlined button of its own width (a [Second] fills the row), with the path's focus mark. */
@Composable
private fun NarrowSecond(text: UiText, enabled: Boolean, onClick: () -> Unit) {
    val (source, mark) = focusMark(text.shown())
    OutlinedButton(onClick = guarded(onClick = onClick), enabled = enabled, modifier = mark, interactionSource = source) { Say(text) }
}

/**
 * The policy (§9.2, spec 03 §7.2): read as the server holds it, edited, and saved with the master password. A value the
 * server refuses is said in a sentence and nothing is stored; sign-up can only be tightened here.
 */
@Composable
private fun PolicySection(op: OperatorModel, s: AppSnapshot, c: OperatorConsole) {
    SectionTitle(Placeholder.OP_POLICY)
    val p = c.policy
    if (p == null) {
        Quiet(UiText.ph(Placeholder.POLICY_NOT_READ))
        return
    }
    Quiet(UiText.ph(Placeholder.OP_POLICY_SUMMARY, p.autoLockSeconds.toString(), p.clipboardClearSeconds.toString(), p.offlineCacheAllowed.toString(), p.signup.mode ?: "-", p.signup.cap?.toString() ?: "-"))
    // Why the last save was refused, by the server's reason, beside the policy until a stored save or a lock clears it.
    policyRefusalText(c)?.let { Say(it, color = MaterialTheme.colorScheme.error) }
    // "Change" with what it, or a read of the policy, answered beside it: no empty slot under it.
    WithSaidBeside({ Quieter(UiText.ph(Placeholder.OP_POLICY_EDIT, plainName(c.instance.name)), enabled = !s.busy) { op.chooseForServer(OperatorModel.Action.POLICY) } }) {
        Column {
            OperatorSaid(op, OperatorModel.Area.POLICY, null, OperatorModel.Action.POLICY)
            OperatorSaid(op, OperatorModel.Area.POLICY)
        }
    }
}

/** [OperatorConsole.policyRefusal] as drawn beside the policy; null while none stands. */
internal fun policyRefusalText(c: OperatorConsole): UiText? = c.policyRefusal?.let { UiText.of(it) }

/** The policy's fields, as read, edited and checked before its password step ([OperatorModel.checkPolicy]). */
@Composable
private fun PolicyInputs(op: OperatorModel, s: AppSnapshot, chosen: OperatorModel.Chosen, p: AdminPolicy) {
    val start = remember(p) { PolicyTyped.of(p) }
    var autoLock by remember(p) { mutableStateOf(start.autoLockSeconds) }
    var clipboard by remember(p) { mutableStateOf(start.clipboardClearSeconds) }
    var offline by remember(p) { mutableStateOf(start.offlineCacheAllowed) }
    var access by remember(p) { mutableStateOf(start.sessionAccessTtlSeconds) }
    var refresh by remember(p) { mutableStateOf(start.sessionRefreshTtlDays) }
    var attach by remember(p) { mutableStateOf(start.attachmentMaxBytes) }
    var itemAttach by remember(p) { mutableStateOf(start.itemAttachmentsMaxBytes) }
    var qBytes by remember(p) { mutableStateOf(start.quotaBytes) }
    var qItems by remember(p) { mutableStateOf(start.quotaItems) }
    var qVaults by remember(p) { mutableStateOf(start.quotaVaults) }
    var qLinks by remember(p) { mutableStateOf(start.quotaLinks) }
    var ops by remember(p) { mutableStateOf(start.kdfOps) }
    var mem by remember(p) { mutableStateOf(start.kdfMemBytes) }
    var mode by remember(p) { mutableStateOf(start.signupMode) }
    var cap by remember(p) { mutableStateOf(start.signupCap) }
    val check = {
        op.checkPolicy(chosen, p, PolicyTyped(autoLock, clipboard, offline, access, refresh, attach, itemAttach, qBytes, qItems, qVaults, qLinks, ops, mem, mode, cap))
        Unit
    }
    StepFrame(UiText.ph(Placeholder.OP_POLICY_EDIT, stepTarget(chosen)), UiText.ph(Placeholder.OP_STEP_NEXT), !s.busy, { op.cancelStep() }, check) {
        StepValues(chosen.values)
        Field(UiText.ph(Placeholder.OP_POLICY_AUTO_LOCK), autoLock, mono = true) { autoLock = it }
        Field(UiText.ph(Placeholder.OP_POLICY_CLIPBOARD), clipboard, mono = true) { clipboard = it }
        Tick(UiText.ph(Placeholder.OP_POLICY_OFFLINE), offline, enabled = !s.busy) { offline = it }
        Field(UiText.ph(Placeholder.OP_POLICY_ACCESS_TTL), access, mono = true) { access = it }
        Field(UiText.ph(Placeholder.OP_POLICY_REFRESH_TTL), refresh, mono = true) { refresh = it }
        Field(UiText.ph(Placeholder.OP_POLICY_ATTACHMENT), attach, mono = true) { attach = it }
        Field(UiText.ph(Placeholder.OP_POLICY_ITEM_ATTACHMENTS), itemAttach, mono = true) { itemAttach = it }
        Say(Placeholder.OP_QUOTA_DEFAULTS_TITLE, style = MaterialTheme.typography.labelMedium)
        Field(UiText.ph(Placeholder.OP_QUOTA_BYTES_DEFAULT), qBytes, mono = true) { qBytes = it }
        Field(UiText.ph(Placeholder.OP_QUOTA_ITEMS_DEFAULT), qItems, mono = true) { qItems = it }
        Field(UiText.ph(Placeholder.OP_QUOTA_VAULTS_DEFAULT), qVaults, mono = true) { qVaults = it }
        Field(UiText.ph(Placeholder.OP_QUOTA_LINKS_DEFAULT), qLinks, mono = true) { qLinks = it }
        Field(UiText.ph(Placeholder.OP_POLICY_KDF_OPS), ops, mono = true) { ops = it }
        Field(UiText.ph(Placeholder.OP_POLICY_KDF_MEM), mem, mono = true) { mem = it }
        Say(Placeholder.OP_POLICY_SIGNUP, style = MaterialTheme.typography.labelMedium)
        Quiet(UiText.Plain(OperatorDesignWords.SIGNUP_TIGHTEN))
        for (m in listOf(null, "open", "links", "closed")) {
            // One placeholder per choice: a gloss inside another showed nested brackets (found in the run).
            val label = if (m == null) UiText.ph(Placeholder.OP_SIGNUP_NOTHING_STORED) else UiText.ph(Placeholder.OP_SIGNUP_MODE, m)
            Choice(label, UiText.Plain(""), selected = mode == m, enabled = !s.busy) { mode = m }
        }
        Field(UiText.ph(Placeholder.OP_POLICY_CAP), cap, mono = true) { cap = it }
        if (p.minVersion.isNotEmpty()) Quiet(UiText.ph(Placeholder.OP_POLICY_MIN_VERSIONS, p.minVersion.entries.joinToString { "${it.key} ${it.value}" }))
        StepSaid(op, OperatorModel.Area.POLICY, null, OperatorModel.Action.POLICY)
    }
}

/** The closed list of reasons to disable an account (the wire's `DisableReason`); the person is told the category. */
internal fun disableWhyLabel(w: DisableWhy): UiText = UiText.ph(
    when (w) {
        DisableWhy.ABUSE -> Placeholder.OP_WHY_ABUSE
        DisableWhy.REQUEST -> Placeholder.OP_WHY_REQUEST
        DisableWhy.OTHER -> Placeholder.OP_WHY_OTHER
    },
)


/** The server as the console names it, what its status says, and "read again". */
@Composable
private fun ConsoleHeader(op: OperatorModel, s: AppSnapshot, c: OperatorConsole) {
    InstanceName(c.instance, MaterialTheme.typography.bodyLarge)
    // Every line a read can add or change here sits in one slot: as tall as what stands in it, so no room is kept for a
    // warning that is not there, and never taller than the header's room, past which its lines scroll inside it. The
    // status line, there after every read, comes first.
    CappedSlot(CONSOLE_HEADER_SLOT) {
        c.status?.let { st ->
            Quiet(UiText.ph(Placeholder.OP_STATUS, st.serverVersion, st.instanceKind, st.signup.mode, st.signup.active.toString(), st.signup.cap.toString(), if (st.signup.full) "full" else "not full"))
        }
        // §6.7 Resume: the server has no identity card yet.
        if (c.setupUnfinished) Say(CopyKey.FINISH_SERVER_SETUP, color = MaterialTheme.colorScheme.error)
        // §11.4: the panel shows a banner while the server's mail is stalled.
        c.status?.mail?.takeIf { it.stalled }?.let { mail ->
            Say(UiText.ph(Placeholder.OP_MAIL_STALLED, mail.oldestQueuedAt?.let { opDate(it) } ?: UiText.ph(Placeholder.OP_NOT_GIVEN).shown()), color = MaterialTheme.colorScheme.error)
        }
        // Rows the shared code would not show: its own line, above the lists.
        c.serverSentBadRowsLine?.let { Say(keyLine(it), color = MaterialTheme.colorScheme.error) }
    }
    // "Read again" with what a read answered beside it: no empty slot under it.
    WithSaidBeside({ Quieter(UiText.ph(Placeholder.OP_READ_AGAIN), enabled = !s.busy) { op.refresh() } }) {
        OperatorSaid(op, OperatorModel.Area.CONSOLE, anyAction = true)
    }
}

/**
 * What an intent of the console answered about [area] (and [key]), in place: beside the control of [action] (and of
 * [about] within it) when one is given, else what a read answered. [anyAction]: every answer about [area] and [key]
 * (the console's top, and above the requests, where what is said of a row the list no longer holds goes). A refused
 * read adds that the list is the last one read. Nothing is said beside an action while its own step is open.
 */
@Composable
internal fun OperatorSaid(op: OperatorModel, area: OperatorModel.Area, key: String? = null, action: OperatorModel.Action? = null, about: String? = null, anyAction: Boolean = false) {
    op.answers.collectAsState().value
    val chosen by op.chosen.collectAsState()
    val step by op.step.collectAsState()
    val open = step?.chosen ?: chosen
    if (action != null && open != null && open.area == area && open.key == key && open.action == action && open.about == about) return
    val a = (if (anyAction) op.answerAt(area, key) else op.answerFor(area, key, action, about)) ?: return
    val refused = a.result?.done != true
    Say(
        a.text,
        Modifier.fillMaxWidth().padding(vertical = 4.dp).semantics { liveRegion = LiveRegionMode.Polite },
        MaterialTheme.typography.bodyMedium,
        if (refused) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (a.previousKept) Quiet(UiText.ph(Placeholder.OP_SHOWING_PREVIOUS))
}

/** A server time as the console shows it: date and time, in this computer's zone. */
internal fun opDate(ms: Long): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(ms))
