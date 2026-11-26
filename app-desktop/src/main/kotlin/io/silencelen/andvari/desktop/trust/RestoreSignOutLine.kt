package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

/**
 * Whether this computer's record of a restore into the signed-in account does not show it as finished, read as a
 * question before a sign-out, a switch to another server or "Forget this server" is drawn: those delete the record.
 */
@Composable
internal fun unfinishedRestore(model: TrustModel): Boolean = guardedRead(null, false) { model.api.restores.unfinishedRestore() }

/** The draft line of such a question while the record does not show the restore as finished (decided on 23 November 2026). */
@Composable
internal fun UnfinishedRestoreLine(model: TrustModel) {
    if (unfinishedRestore(model)) Say(UiText.ph(Placeholder.RESTORE_UNFINISHED_AT_SIGN_OUT), color = MaterialTheme.colorScheme.error)
}
