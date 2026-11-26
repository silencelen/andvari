package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EarlierAccountKnown
import io.silencelen.andvari.core.app.NewAccountRememberedNotice

// "Forget the earlier account on this device" (decided on 2026-11-17). This phone remembers, for an address at a
// server, which account it is; a person who deleted their account and made it again under the same address is refused
// for good. The shared code says so in AppSnapshot.earlierAccount, on the refused screen only, and this app draws it
// exactly as it comes: the refusal with both possibilities, the offer, its second step, and the result's line. Never
// offered anywhere else, never preselected, never taken by the app itself.

/**
 * What the offer says, each a sentence of its own, in the shared code's order: at its first step the heading, the refusal
 * (the address and the server), the two possibilities (the account was deleted and made again; or the server is not
 * giving this phone the account it knows) and how to tell, neither preferred; at its second step the confirmation's
 * heading and every line it carries (what goes; a copy of the account kept here, with how many of its changes were not
 * sent or that this phone cannot tell; that it cannot be undone and what it means if the account was not made again).
 */
internal fun earlierAccountLines(offer: EarlierAccountKnown): List<UiText> =
    if (!offer.confirming) {
        listOf(UiText.of(offer.title), UiText.of(offer.refusal), UiText.of(offer.ifRemade), UiText.of(offer.ifServer), UiText.of(offer.howToTell))
    } else {
        listOfNotNull(offer.confirmTitle?.let { UiText.of(it) }) + offer.confirmLines.map { UiText.of(it) }
    }

/**
 * The offer under the refused result's line ([SaidHere]), on the screen it was raised on. Two buttons of the same
 * weight, neither default nor focused, neither bound to Enter or Back: the step's own (the offer's "Forget the earlier
 * account on this device", or the confirmation's) and Cancel. Each reads the offer on show at the tap ([TrustModel]).
 */
@Composable
internal fun EarlierAccountOffer(model: TrustModel, s: AppSnapshot, offer: EarlierAccountKnown) {
    if (s.phase != AppPhase.ENTRY) return
    Gap(8)
    earlierAccountLines(offer).forEachIndexed { i, line ->
        Say(line, style = if (i == 0) MaterialTheme.typography.titleSmall else MaterialTheme.typography.bodyMedium)
    }
    Gap(8)
    val confirm = offer.confirmLabel
    if (offer.confirming && confirm != null) {
        Second(UiText.of(confirm), enabled = !s.busy) { model.forgetEarlierAccount() }
    } else {
        Second(UiText.of(offer.forgetLabel), enabled = !s.busy) { model.askToForgetEarlierAccount() }
    }
    Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.keepEarlierAccount() }
}

/**
 * After a deletion whose outcome is not known (its deletion screen, its lock screen, the first screen's notice): the
 * shared code's offer to forget that account on this phone ([io.silencelen.andvari.core.app.ForgetUnknownDeletion]),
 * drawn as the other forgetting is. The offer; on its tap the second step with the confirmation's line and what goes
 * of the changes not sent; two buttons of the same weight, neither default nor focused. Each reads the check at the tap.
 */
@Composable
internal fun ForgetUnknownDeletionOffer(model: TrustModel, s: AppSnapshot, section: String? = null) {
    val check = model.forgetUnknownCheck() ?: return
    val asked by model.forgetUnknownAsked.collectAsState()
    Gap(8)
    for (line in forgetUnknownLines(check, confirming = asked === check)) Say(line)
    Gap(8)
    if (asked === check) {
        Second(UiText.ph(Placeholder.FORGET_UNKNOWN_DELETION_CONFIRM), enabled = !s.busy) { model.forgetUnknownDeletion(section) }
        Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.keepUnknownDeletion() }
    } else {
        Second(UiText.of(check.offerLine), enabled = !s.busy) { model.askToForgetUnknownDeletion() }
    }
}

/** The second step's lines: the confirmation, then how many changes not sent go (or that this phone cannot tell). The offer itself is its button. */
internal fun forgetUnknownLines(check: io.silencelen.andvari.core.app.ForgetUnknownDeletion, confirming: Boolean): List<UiText> =
    if (confirming) listOf(UiText.of(check.confirmLine), UiText.of(check.unsentLine)) else emptyList()

/** After a forgetting, the next account under the address was taken here: said once above any screen, until dismissed. */
@Composable
internal fun NewAccountRememberedView(model: TrustModel, notice: NewAccountRememberedNotice) {
    Column(Modifier.windowInsetsPadding(WindowInsets(16, 8, 16, 8))) {
        Say(notice.line)
        Quieter(UiText.ph(Placeholder.DISMISS)) { model.dismissNewAccountRemembered(notice) }
    }
}
