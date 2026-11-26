package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EarlierAccountKnown

// "Forget the earlier account on this device" (decided on 2026-11-17). This computer remembers which account an address at
// a server is, and refuses another account under it. Where that refusal is the shared code's own, the snapshot carries the
// offer ([AppSnapshot.earlierAccount]) while the refused screen is on show: the window draws it as it comes and keeps
// nothing of it, so a lock, a screen change or a restart (each of which the shared code takes it back at) leaves nothing
// of a confirmation here.

/** The offer's first step, each a sentence of its own, in the shared code's order: what was refused, both possibilities, how to tell. */
internal fun earlierOfferLines(offer: EarlierAccountKnown): List<UiText> =
    listOf(UiText.of(offer.title), UiText.of(offer.refusal), UiText.of(offer.ifRemade), UiText.of(offer.ifServer), UiText.of(offer.howToTell))

/** The second step: its heading and every line the confirmation carries, in order; empty while it is not on show. */
internal fun earlierConfirmLines(offer: EarlierAccountKnown): List<UiText> =
    if (!offer.confirming) emptyList() else listOfNotNull(offer.confirmTitle?.let { UiText.of(it) }) + offer.confirmLines.map { UiText.of(it) }

/** What the forgetting's answer says, for the offer it was asked on; null for STALE (the snapshot shows what holds). */
internal fun earlierResultLine(offer: EarlierAccountKnown, r: io.silencelen.andvari.core.app.ForgetEarlierResult): UiText? =
    offer.lineFor(r)?.let { UiText.of(it) }

/**
 * The offer under the refused answer's line, on the screen it was raised on. The first step: the refusal with both
 * possibilities, then "Forget the earlier account on this device" and Cancel, alike in weight; neither is the default
 * button, neither is focused or bound to Enter. "Forget" only asks the shared code for the second step. The second step:
 * every line of the confirmation, Cancel first, then the button that forgets, which alone calls the forgetting, only from
 * the person's own click, with the confirmation on show. A forgetting that threw is said as a fault and leaves the second
 * step on show for the person's next click; the app never tries it again by itself.
 */
@Composable
internal fun EarlierAccountOffer(model: TrustModel, s: AppSnapshot) {
    val offer = s.earlierAccount ?: return
    Column(Modifier.padding(vertical = 8.dp)) {
        val lines = earlierOfferLines(offer)
        Say(lines.first(), style = MaterialTheme.typography.titleSmall)
        for (line in lines.drop(1)) Say(line)
        val cancel = UiText.of(CopyKey.CANCEL)
        if (!offer.confirming) {
            Gap(8)
            Second(UiText.of(offer.forgetLabel), enabled = !s.busy) { model.quietly { model.api.entry.askToForgetEarlierAccount(offer) } }
            Second(cancel, enabled = !s.busy) { model.quietly { model.api.entry.keepEarlierAccount(offer) } }
            return@Column
        }
        Gap(8)
        val confirm = earlierConfirmLines(offer)
        confirm.firstOrNull()?.let { Say(it, style = MaterialTheme.typography.titleSmall) }
        for (line in confirm.drop(1)) Say(line, color = MaterialTheme.colorScheme.error)
        Second(cancel, enabled = !s.busy) { model.quietly { model.api.entry.keepEarlierAccount(offer) } }
        offer.confirmLabel?.let { label ->
            Second(UiText.of(label), enabled = !s.busy) {
                model.runSaying({ entry.forgetEarlierAccount(offer) }, words = { r -> earlierResultLine(offer, r) })
            }
        }
    }
}

/** The second step of forgetting after a deletion whose outcome is not known: its confirmation, then what goes unsent. */
internal fun forgetUnknownConfirmLines(check: io.silencelen.andvari.core.app.ForgetUnknownDeletion): List<UiText> =
    listOf(UiText.of(check.confirmLine), UiText.of(check.unsentLine))

/**
 * After a deletion whose outcome is not known (the deletion's screen, the lock screen, the first screen): the shared
 * code's offer to forget that account on this computer ([TrustModel.forgetUnknownCheck]), drawn as the other forgetting
 * is. The first step is the offer alone; its tap only shows the second step. The second step: the confirmation and the
 * line about changes not sent, Cancel first, then the button that forgets, which alone calls the forgetting, only from
 * the person's own click. Neither step's button is the default, focused or bound to a key. The model closes the second
 * step at a lock, at another phase and when the shared code's offer is a new object ([TrustModel.forgetUnknownAsked]).
 */
@Composable
internal fun ForgetUnknownDeletionOffer(model: TrustModel, s: AppSnapshot) {
    val asked = model.forgetUnknownAsked.collectAsState().value
    val check = model.forgetUnknownCheck() ?: return
    Column(Modifier.padding(vertical = 8.dp)) {
        if (asked !== check) {
            Second(UiText.of(check.offerLine), enabled = !s.busy) { model.askToForgetAfterUnknownDeletion(check) }
            return@Column
        }
        for (line in forgetUnknownConfirmLines(check)) Say(line, color = MaterialTheme.colorScheme.error)
        Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.keepAfterUnknownDeletion() }
        Second(UiText.ph(Placeholder.FORGET_UNKNOWN_CONFIRM), enabled = !s.busy) { model.forgetAfterUnknownDeletion(check) }
    }
}

/**
 * After the person forgot an earlier account, the next account taken under that address: said once above whatever is on
 * show ([AppSnapshot.rememberedNewAccount]), until dismissed.
 */
@Composable
internal fun NewAccountRememberedBar(model: TrustModel, s: AppSnapshot) {
    val notice = s.rememberedNewAccount ?: return
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Say(UiText.of(notice.line))
        Quieter(UiText.ph(Placeholder.DISMISS)) { model.quietly { model.api.dismissNewAccountRemembered(notice) } }
    }
}
