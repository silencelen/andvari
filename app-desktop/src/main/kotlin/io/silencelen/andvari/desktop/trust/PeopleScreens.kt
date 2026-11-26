package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.CopyKey

// The prompts that wait for an answer, people, and the two comparison codes (§6.11), ported from the Android app.

/**
 * Every prompt waiting for an answer, each with the answers the API gives it, as the current app's attention area: one
 * card per prompt, the area capped in height and scrolled inside, so a pile-up neither clips its lower cards nor
 * squeezes the page under it. [openRecovery] opens Settings' recovery section, where a request the alert could not read
 * is listed and cancelled.
 */
@Composable
internal fun PromptsSection(model: TrustModel, s: AppSnapshot, prompts: List<AccountPrompt>, openSharing: () -> Unit = {}, openRecovery: () -> Unit = {}) {
    if (prompts.isEmpty()) return
    Say(Placeholder.PROMPTS, style = MaterialTheme.typography.titleSmall)
    Column(Modifier.fillMaxWidth().heightIn(max = ATTENTION_AREA_MAX.dp).verticalScroll(rememberScrollState())) {
        for (p in prompts) AttentionCard(p) { PromptView(model, s, p, openSharing, openRecovery) }
    }
}

/** The current app's cap on the attention area's height. */
internal const val ATTENTION_AREA_MAX = 360

/**
 * One prompt's card, as the current app's attention cards: a card of the page's own surface, its line and answers inside
 * with room around them, and no edge marks. A change of the recovery key, or the question whether to keep operator
 * recovery, stands in the tertiary container, as the current app's card for a changed recovery key.
 */
@Composable
internal fun AttentionCard(p: AccountPrompt, content: @Composable () -> Unit) {
    val recoveryKey = p is AccountPrompt.RecoveryKeyChanged || p is AccountPrompt.KeepOperatorRecovery
    Card(
        Modifier.fillMaxWidth().padding(vertical = 6.dp),
        colors = if (recoveryKey) CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer) else CardDefaults.cardColors(),
    ) {
        Column(Modifier.padding(16.dp)) { content() }
    }
}

/**
 * §9.3 step 2 on a signed-in device: under the alert's line, each request with the shared code's row line (when it was
 * asked, the device as the server says it, when the wait ends) and every flag it carries, then Cancel for it; "This was
 * me" once for the alert. When the server says there is a request this device could not read, the shared sentence and
 * the way to Settings' recovery section, where it is listed and cancelled.
 */
@Composable
private fun RecoveryRequestAlert(model: TrustModel, s: AppSnapshot, p: AccountPrompt.RecoveryRequest, openRecovery: () -> Unit) {
    if (p.unreadable) {
        Say(UiText.of(CopyKey.RECOVERY_REQUEST_UNREADABLE), color = MaterialTheme.colorScheme.error)
        Second(UiText.ph(Placeholder.RECOVERY_SETTINGS), enabled = !s.busy) { openRecovery() }
    }
    for (r in p.requests) {
        Quiet(requestDetailLine(p.rowLine, r))
        for (flag in requestFlags(r)) Say(UiText.of(flag), color = MaterialTheme.colorScheme.error)
        // Cancelling is the answer the alert asks for; it comes first and is signed by this account's key.
        Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ recovery.cancelRecoveryRequest(r) }) }
    }
    if (p.requests.isNotEmpty()) Quieter(UiText.of(p.wasMe), enabled = !s.busy) { model.act { recovery.recoveryRequestWasMe(p) } }
}

@Composable
private fun PromptView(model: TrustModel, s: AppSnapshot, p: AccountPrompt, openSharing: () -> Unit, openRecovery: () -> Unit) {
    // The card's head, as the current app's attention cards name what they ask.
    Say(promptLine(p), style = MaterialTheme.typography.titleSmall)
    Gap(6)
    when (p) {
        is AccountPrompt.IncomingVault -> {
            Second(UiText.of(CopyKey.INCOMING_ACCEPT), enabled = !s.busy) { model.run({ vaults.acceptIncoming(p) }) }
            Quieter(UiText.of(CopyKey.INCOMING_DECLINE), enabled = !s.busy) { model.run({ vaults.declineIncoming(p) }) }
        }
        // A contact answered under a new key (§6.8 step 6): its one action opens the comparison, which stands on the
        // Sharing page with the people. The prompt stays until a matched comparison replaces the key.
        is AccountPrompt.KeyChanged ->
            Second(UiText.of(CopyKey.COMPARE_CODES), enabled = !s.busy) { model.run({ contacts.openCompareForNewKey(p) }) { if (it.done) openSharing() } }
        is AccountPrompt.NewPerson -> {
            // Approved entry 18: the hint under the existing sentence, and its two answers.
            Say(UiText.approved("PERSON_FROM_OTHER_DEVICE_HINT.body"))
            Second(UiText.approved("PERSON_FROM_OTHER_DEVICE_HINT.button0"), enabled = !s.busy) { model.run({ contacts.useOnThisDevice(p) }) }
            Quieter(UiText.approved("PERSON_FROM_OTHER_DEVICE_HINT.button1"), enabled = !s.busy) { model.act { contacts.dontUseOnThisDevice(p) } }
        }
        is AccountPrompt.PeopleList -> PeopleListView(model, s, p)
        is AccountPrompt.RecoveryRequest -> RecoveryRequestAlert(model, s, p, openRecovery)
        is AccountPrompt.RecoveryKeyChanged -> {
            var password by remember(p) { mutableStateOf("") }
            Say(p.body)
            MasterPasswordField(s, password) { password = it }
            // "Turn off operator recovery" is the default.
            Main(UiText.of(CopyKey.RECOVERY_KEY_CHANGED_TURN_OFF), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
                val pw = password
                model.run({ recovery.answerRecoveryKeyChanged(p, false, pw) }) { password = "" }
            }
            Second(UiText.of(CopyKey.RECOVERY_KEY_CHANGED_KEEP), enabled = password.isNotEmpty() && !s.busy) {
                val pw = password
                model.run({ recovery.answerRecoveryKeyChanged(p, true, pw) }) { password = "" }
            }
            Quieter(UiText.of(CopyKey.RECOVERY_KEY_CHANGED_LATER), enabled = !s.busy) { model.act { recovery.recoveryKeyChangedLater(p) } }
        }
        is AccountPrompt.KeepOperatorRecovery -> {
            var password by remember(p) { mutableStateOf("") }
            // "Not now" is the default: it sends nothing.
            Main(UiText.of(CopyKey.KEEP_OPERATOR_NOT_NOW), enabled = !s.busy, busy = false) { model.act { recovery.keepOperatorRecoveryNotNow(p) } }
            MasterPasswordField(s, password) { password = it }
            Second(UiText.of(CopyKey.KEEP_OPERATOR_KEEP), enabled = password.isNotEmpty() && !s.busy) {
                val pw = password
                model.run({ recovery.answerKeepOperatorRecovery(p, true, pw) }) { password = "" }
            }
            Quieter(UiText.of(CopyKey.KEEP_OPERATOR_TURN_OFF), enabled = password.isNotEmpty() && !s.busy) {
                val pw = password
                model.run({ recovery.answerKeepOperatorRecovery(p, false, pw) }) { password = "" }
            }
        }
        is AccountPrompt.ConnectionNotMade -> {
            if (p.canRetry) Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { model.linkName.go(NamedLinkAct.Retry(p)) }
            Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.act { links.dropConnection(p) } }
        }
        // §6.7 Resume: the operator's server has no card pinned; finished here, with its own password step.
        is AccountPrompt.FinishServerSetup -> FinishServerSetupPrompt(model, s, p)
    }
}

/** The list "People you've connected with": every row ticked, "Use these on this device" and "Later". */
@Composable
private fun PeopleListView(model: TrustModel, s: AppSnapshot, p: AccountPrompt.PeopleList) {
    var ticked by remember(p) { mutableStateOf(p.people.map { it.userId }.toSet()) }
    Say(p.body)
    for (person in p.people) {
        Tick(UiText.Plain(person.label), person.userId in ticked) { on -> ticked = if (on) ticked + person.userId else ticked - person.userId }
    }
    Second(UiText.of(CopyKey.PEOPLE_USE), enabled = ticked.isNotEmpty() && !s.busy) {
        val ids = p.people.map { it.userId }.filter { it in ticked }
        model.run({ contacts.usePeople(p, ids) })
    }
    Quieter(UiText.of(CopyKey.PEOPLE_LATER), enabled = !s.busy) { model.act { contacts.peopleLater(p) } }
}

/** A contact's state line: compared, or not yet. */
internal fun contactLine(c: ContactRow): UiText =
    UiText.ph(if (c.compared) Placeholder.CONTACT_COMPARED else Placeholder.CONTACT_NOT_COMPARED, c.label)

/**
 * People: each contact compared or not, "confirm on this device" when it is not current here, "Compare codes" when the
 * codes are ready, remove. A comparison in progress shows above the list ([CompareView]).
 */
@Composable
internal fun PeopleSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    account.comparing?.let { CompareView(model, s, it) }
    val screen = account.contacts
    if (screen == null) return ClosedSection(Placeholder.PEOPLE, enabled = !s.busy) { model.run({ contacts.openContacts() }) }
    SectionTitle(Placeholder.PEOPLE)
    // Approved entry 19: a notice at the top until the list is answered; its button raises the list again.
    if (screen.peopleNotReviewed) {
        Say(UiText.approved("PEOPLE_NOT_REVIEWED.body"))
        Second(UiText.approved("PEOPLE_NOT_REVIEWED.button0"), enabled = !s.busy) { model.act { contacts.reviewPeople(screen) } }
    }
    // An open list with nobody in it says so, rather than a title over a lone "close".
    if (screen.contacts.isEmpty()) Say(UiText.ph(Placeholder.PEOPLE_NONE), Modifier.padding(vertical = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
    for (c in screen.contacts) {
        // A person is a row with their letter, as a vault and an item are.
        LetterHead(c.label, contactLine(c))
        if (!c.currentHere) Second(UiText.of(CopyKey.CONFIRM_ON_THIS_DEVICE), enabled = !s.busy) { model.run({ contacts.confirmOnThisDevice(c) }) }
        if (offersCompare(c)) Second(UiText.of(CopyKey.COMPARE_CODES), enabled = !s.busy) { model.run({ contacts.openCompare(c) }) }
        Quieter(UiText.ph(Placeholder.CONTACT_REMOVE), enabled = !s.busy) { model.run({ contacts.removeContact(c) }) }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { contacts.closeContacts() } }
}

/**
 * "Compare codes" is offered for a person not compared yet where the shared code says a comparison can be opened
 * ([ContactRow.canCompare]): codes ready, or, on the side that answered a link, the creator's reveal not fetched yet
 * (opening the comparison fetches it, and says it is waiting for the code until it comes). Never for a link that failed.
 */
internal fun offersCompare(c: ContactRow): Boolean = !c.compared && c.canCompare

/**
 * The comparison may be submitted: six digits typed (§6.11, §17). This device's own code typed back is the shared
 * code's to judge, as on Android: it answers that the codes do not match, except on the one link in a million whose two
 * codes are equal, where it is the right entry and a refusal here would have left that comparison with no way through.
 */
internal fun comparisonReady(@Suppress("UNUSED_PARAMETER") c: CompareScreen.Ready, typed: String): Boolean = deviceDigitsReady(typed)

/**
 * Comparing codes (§6.11): Waiting has no code yet; Ready shows this device's own six digits to read out and a field
 * for the six the other person reads. There is no "they match" button (§17): the only path to a match is
 * `submitComparison` with what was typed, as typed.
 */
@Composable
internal fun CompareView(model: TrustModel, s: AppSnapshot, c: CompareScreen) {
    Say(UiText.of(CopyKey.COMPARE_CODES), style = MaterialTheme.typography.titleSmall)
    Text(c.label, style = MaterialTheme.typography.bodyLarge)
    when (c) {
        is CompareScreen.Waiting -> Quiet(UiText.ph(Placeholder.COMPARE_WAITING))
        is CompareScreen.Ready -> {
            var theirs by remember(c) { mutableStateOf("") }
            val submit = {
                if (comparisonReady(c, theirs) && !s.busy) {
                    val d = theirs
                    model.run({ contacts.submitComparison(c, d) }) { theirs = "" }
                }
            }
            // Approved entry 21: the first line beside this device's own code, the second beside the field.
            Say(UiText.approvedLine("COMPARE_READ_AND_TYPE.body", 0, c.label))
            Text(c.code.chunked(3).joinToString(" "), style = MaterialTheme.typography.headlineMedium.copy(fontFamily = FontFamily.Monospace))
            Say(UiText.approvedLine("COMPARE_READ_AND_TYPE.body", 1, c.label))
            Field(UiText.ph(Placeholder.COMPARE_THEIR_CODE), theirs, mono = true, onEnter = { submit() }) { theirs = it }
            Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = deviceDigitsReady(theirs) && !s.busy, busy = s.busy) { submit() }
        }
        is CompareScreen.LinkFailed -> Say(UiText.ph(Placeholder.COMPARE_LINK_FAILED))
        is CompareScreen.Matched -> Say(UiText.ph(Placeholder.COMPARE_MATCHED))
    }
    // What a submit answered is said at the top of the shell (SaidHere), with every other answer of this screen.
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { contacts.closeCompare() } }
    HorizontalDivider()
}
