package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.CopyKey

// ---- the prompts, with their answers (map §3.16, §3.22) ----

/** Every prompt waiting for an answer, each with the answers the API gives it. */
@Composable
internal fun PromptsSection(model: TrustModel, s: AppSnapshot, prompts: List<AccountPrompt>) {
    if (prompts.isEmpty()) return
    Say(Placeholder.PROMPTS, style = MaterialTheme.typography.titleSmall)
    for (p in prompts) {
        PromptView(model, s, p)
        HorizontalDivider()
    }
}

@Composable
private fun PromptView(model: TrustModel, s: AppSnapshot, p: AccountPrompt) {
    // The recovery alert says its own line, in the error colour, with what belongs under it.
    if (p !is AccountPrompt.RecoveryRequest) Say(promptLine(p), style = MaterialTheme.typography.bodyMedium)
    when (p) {
        is AccountPrompt.IncomingVault -> {
            Second(UiText.of(CopyKey.INCOMING_ACCEPT), enabled = !s.busy) { model.run({ vaults.acceptIncoming(p) }) }
            Quieter(UiText.of(CopyKey.INCOMING_DECLINE), enabled = !s.busy) { model.run({ vaults.declineIncoming(p) }) }
        }
        is AccountPrompt.KeyChanged ->
            Second(UiText.of(CopyKey.COMPARE_CODES), enabled = !s.busy) { model.run({ contacts.openCompareForNewKey(p) }) }
        is AccountPrompt.NewPerson -> {
            // Under the design's sentence, the approved hint and the two answers (copy page, entry 18).
            Quiet(UiText.Plain(Approved.PERSON_FROM_OTHER_DEVICE_HINT))
            Second(UiText.Plain(Approved.PERSON_USE_ON_THIS_DEVICE), enabled = !s.busy) { model.run({ contacts.useOnThisDevice(p) }) }
            Quieter(UiText.Plain(Approved.PERSON_DONT_USE), enabled = !s.busy) { model.act { contacts.dontUseOnThisDevice(p) } }
        }
        is AccountPrompt.PeopleList -> PeopleListView(model, s, p)
        is AccountPrompt.RecoveryRequest -> RecoveryRequestAlert(model, s, p)
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
            // Sending the answer again carries the account's name: asked first when this phone keeps none (§6.7).
            if (p.canRetry) Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { model.linkAct(TrustModel.LinkAct.RetryConnection(p)) }
            Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.act { links.dropConnection(p) } }
        }
        // The operator's server setup is finished on a computer; Android has no operator screens.
        is AccountPrompt.FinishServerSetup -> {}
    }
}

/** The one-tap list "People you've connected with": every row ticked, "Use these on this device" and "Later". */
@Composable
private fun PeopleListView(model: TrustModel, s: AppSnapshot, p: AccountPrompt.PeopleList) {
    var ticked by remember(p) { mutableStateOf(p.people.map { it.userId }.toSet()) }
    Say(p.body)
    for (person in p.people) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = person.userId in ticked, onCheckedChange = { on -> ticked = if (on) ticked + person.userId else ticked - person.userId })
            Text(person.label)
        }
    }
    Second(UiText.of(CopyKey.PEOPLE_USE), enabled = ticked.isNotEmpty() && !s.busy) {
        val ids = p.people.map { it.userId }.filter { it in ticked }
        model.run({ contacts.usePeople(p, ids) })
    }
    Quieter(UiText.of(CopyKey.PEOPLE_LATER), enabled = !s.busy) { model.act { contacts.peopleLater(p) } }
}

// ---- people and the two comparison codes (map §3.11, §3.22) ----

/** A contact's state line: compared, or not yet; and whether it is current on this device. */
internal fun contactLine(c: ContactRow): UiText =
    UiText.ph(if (c.compared) Placeholder.CONTACT_COMPARED else Placeholder.CONTACT_NOT_COMPARED, c.label)

/**
 * "Compare codes" on a person's row: where the shared code says the comparison can be opened
 * ([io.silencelen.andvari.core.app.ContactRow.canCompare]), also for the side that ANSWERED a link before the other side's
 * code arrived (opening it then waits for that code), and only until the codes were compared.
 */
internal fun offersCompare(c: io.silencelen.andvari.core.app.ContactRow): Boolean = c.canCompare && !c.compared

/**
 * People (§3.22): each contact compared or not, "confirm on this device" when it is not current here, "Compare codes"
 * where the comparison can be opened ([offersCompare]), remove. A comparison opens as a screen of its own ([ComparePage]).
 */
@Composable
internal fun PeopleSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    SectionDivider()
    val screen = account.contacts
    if (screen == null) {
        Quieter(UiText.ph(Placeholder.PEOPLE), enabled = !s.busy) { model.run({ contacts.openContacts() }) }
        return
    }
    Say(UiText.ph(Placeholder.PEOPLE), style = sectionTitleStyle())
    for (c in screen.contacts) {
        Say(contactLine(c))
        if (!c.currentHere) Second(UiText.of(CopyKey.CONFIRM_ON_THIS_DEVICE), enabled = !s.busy) { model.run({ contacts.confirmOnThisDevice(c) }) }
        if (offersCompare(c)) Second(UiText.of(CopyKey.COMPARE_CODES), enabled = !s.busy) { model.run({ contacts.openCompare(c) }) }
        Quieter(UiText.ph(Placeholder.CONTACT_REMOVE), enabled = !s.busy) { model.run({ contacts.removeContact(c) }) }
    }
    if (screen.peopleNotReviewed) {
        Say(UiText.Plain(Approved.PEOPLE_NOT_REVIEWED))
        Quieter(UiText.Plain(Approved.PEOPLE_REVIEW_THE_LIST), enabled = !s.busy) { model.act { contacts.reviewPeople(screen) } }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { contacts.closeContacts() } }
}

/**
 * The comparison of codes as a screen of its own, opened from the prompt that a contact's key changed or from People:
 * its title in the top bar, what the last entry answered at the top ([SaidHere]), then [CompareView]. Back and the top
 * bar's arrow close it, as its Close does; nothing is decided by leaving.
 */
@Composable
internal fun ComparePage(model: TrustModel, s: AppSnapshot, c: CompareScreen) {
    ActiveBackHandler(model, enabled = !s.busy) { model.act { contacts.closeCompare() } }
    PageScaffold(UiText.of(CopyKey.COMPARE_CODES), onBack = { model.act { contacts.closeCompare() } }) {
        SaidHere(model, s)
        CompareView(model, s, c)
    }
}

/**
 * Comparing codes (§6.11): Waiting has no code yet; Ready shows this device's own six digits to read out and a field
 * for the six the other person reads. There is no "they match" button. What is typed always goes to the shared code,
 * which alone decides (for about one link in a million the two codes are equal, and this device's own code is then the
 * right entry); a mismatch that is this device's own code typed back says so ([comparisonWords]).
 */
@Composable
internal fun CompareView(model: TrustModel, s: AppSnapshot, c: CompareScreen) {
    Text(c.label, style = MaterialTheme.typography.titleMedium)
    when (c) {
        is CompareScreen.Waiting -> Quiet(UiText.ph(Placeholder.COMPARE_WAITING))
        is CompareScreen.Ready -> {
            var theirs by remember(c) { mutableStateOf("") }
            // A match here replaces the key pinned for this person: the prompt's own line says why the codes are asked.
            if (c.replacesKey) Say(UiText.of(CopyKey.CONTACT_KEY_CHANGED, c.label))
            Say(UiText.approved(Approved.COMPARE_READ_THIS, c.label))
            Text(c.code.chunked(3).joinToString(" "), style = MaterialTheme.typography.headlineMedium.copy(fontFamily = FontFamily.Monospace))
            // The approved second line is a sentence, too long for a field's floating label: it stands above the field
            // and is the field's label too (no floating label; the line is what a screen reader names it by).
            val typeTheirs = UiText.approved(Approved.COMPARE_TYPE_THEIRS, c.label)
            Say(typeTheirs)
            LineLabelledField(typeTheirs, theirs, KeyboardType.NumberPassword, mono = true) { theirs = it }
            Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = theirs.length == 6 && !s.busy, busy = s.busy) {
                val d = theirs
                model.runSaying({ contacts.submitComparison(c, d) }, { r -> comparisonWords(model, c, d, r) }) { theirs = "" }
            }
        }
        is CompareScreen.LinkFailed -> Say(UiText.ph(Placeholder.COMPARE_LINK_FAILED))
        is CompareScreen.Matched -> Say(UiText.ph(Placeholder.COMPARE_MATCHED))
    }
    // What a submit answered is said at the top of the page (SaidHere).
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { contacts.closeCompare() } }
}

/** This device's own code, typed back (digits only). It proves nothing unless the shared code accepts it. */
internal fun ownCodeTypedBack(c: CompareScreen.Ready, typed: String): Boolean = typed.filter { it.isDigit() } == c.code.filter { it.isDigit() }

/**
 * What an entry answered: a mismatch that is this device's own code typed back says that it is the person's own code;
 * every other answer as the app says it anywhere. The entry is never refused here: the shared code decides (§6.11,
 * "an implementation must not refuse a typed code for being equal to its own").
 */
internal fun comparisonWords(model: TrustModel, c: CompareScreen.Ready, typed: String, r: ComparisonResult): UiText? =
    if (r == ComparisonResult.MISMATCH && ownCodeTypedBack(c, typed)) UiText.ph(Placeholder.COMPARE_OWN_CODE_REFUSED) else model.wordsFor(r)
