package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.font.FontFamily
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.app.Sigil
import io.silencelen.andvari.app.BrandSigil
import io.silencelen.andvari.app.SigilMark
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.VaultUnlockResult

/**
 * The lock screen of a stored session (IF-3 author note 5): it names the account, the instance and its origin
 * (`locked.prompt.title`, §4.4), takes the master password, and nothing else is sent. Under a fork the unlock still
 * opens what this device holds, read-only (§4.4 "a fork stops traffic, not reading"); a damaged pin record blocks it,
 * and the ways on are signing out and forgetting the server.
 */
@Composable
internal fun LockScreen(model: TrustModel, s: AppSnapshot, locked: LockedScreen) {
    var password by remember { mutableStateOf("") }
    AuthColumn(verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        // At the largest font sizes the mark alone: the wordmark's two lines would push the password field below the
        // first screen of a small phone (as the drawn screen showed).
        if (largeFont()) SigilMark(BrandSigil, 32.dp) else Sigil()
        Gap()
        // The title names the account, the server and its address; they are not named a second time under it.
        PasswordStepTitle(lockTitle(locked), locked.prompt.instance)
        val instance = s.instance
        when (instance?.card) {
            is InstanceCardState.Stopped -> Say(CopyKey.CARD_FORK, color = MaterialTheme.colorScheme.error)
            is InstanceCardState.Damaged -> {
                CardRecordDamaged(instance.label.origin)
                ForgetServerButton(model, s, instance)
            }
            else -> {}
        }
        // A session the server ended (design §4.4): the copy stays, the password opens it read-only, and the ways on
        // are signing in again (which takes the copy back for this account) and signing out (which deletes it).
        // A session this phone could not confirm with its server ended here, not by its server: its own line in place.
        lockEndLine(locked, signOutWayOutStands(s))?.let { Say(it, color = MaterialTheme.colorScheme.error) }
        // Under a server policy that forbids keeping data here, this phone keeps no key that opens the account: every
        // unlock asks the server, and the shared code's line says so while it holds.
        lockKeysAtServerLine(locked)?.let { Say(it) }
        // A password change this phone's copy could not follow: the previous password opens the copy here.
        if (locked.previousPasswordOpensCopy) Say(UiText.ph(Placeholder.LOCK_PREVIOUS_PASSWORD_OPENS), color = MaterialTheme.colorScheme.error)
        // A deletion whose outcome is still unknown: never "deleted", and never a sign-out that reads as one.
        lockDeletionLine(locked.deletionOutcomeUnknown, model.deletionCannotTell(s))?.let { Say(it, color = MaterialTheme.colorScheme.error) }
        // There, the shared code's offer to forget the account on this phone, behind its second step.
        if (locked.deletionOutcomeUnknown) ForgetUnknownDeletionOffer(model, s)
        Gap(24)
        // The current app's lock screen: what the last try answered stands above the field, then the field, Unlock, and
        // the quiet line while the password is being checked, right under the button that started it.
        SaidHere(model, s)
        SecretField(UiText.ph(Placeholder.PASSWORD_FIELD).shown(), password, onDone = { if (password.isNotEmpty() && !s.busy) submitUnlock(model, locked, password) { password = "" } }) { password = it }
        Gap()
        Main(UiText.ph(Placeholder.UNLOCK_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
            submitUnlock(model, locked, password) { password = "" }
        }
        if (s.busy) Quiet(UiText.ph(Placeholder.UNLOCKING))
        // Author note 1: the biometric button only while the API offers it; the password field stays always.
        if (locked.quickUnlock) {
            Second(UiText.ph(Placeholder.QUICK_UNLOCK_BUTTON), enabled = !s.busy) {
                model.runSaying({ quickUnlock(locked) }, { quickUnlockWords(it, model.api.retryAfterSeconds()) })
            }
        }
        if (locked.signedOutByServer) {
            Second(UiText.ph(Placeholder.SIGN_IN_AGAIN), enabled = !s.busy) { model.act { signInAgain(locked) } }
        }
        Gap()
        SignOutButton(model, s)
    }
}

/**
 * The lock screen's line about a deletion whose outcome is unknown: the shared code's
 * [LockedScreen.deletionOutcomeUnknown], kept across locks and restarts, says "we cannot tell yet"; the app's own
 * inference from this process ([TrustModel.deletionCannotTell]) still speaks when the shared code is silent. Never "deleted".
 */
internal fun lockDeletionLine(coreSaysUnknown: Boolean, appCannotTell: Boolean): UiText? = when {
    coreSaysUnknown -> UiText.ph(Placeholder.LOCK_DELETION_OUTCOME_UNKNOWN)
    appCannotTell -> UiText.ph(Placeholder.DELETION_CANNOT_TELL)
    else -> null
}

/**
 * The lock screen's line for a session that ended: the shared code's own line where it hands one ([LockedScreen.endLine]:
 * a session this phone could not confirm with its server, never "signed out by its server" for it; a session the server
 * ended while the account's keys are kept at the server, which claims no copy here); the server's end otherwise.
 */
internal fun lockEndLine(locked: LockedScreen, besideSignOut: Boolean = false): UiText? = when {
    // A way out that signs this kept account OUT stands on the screen ([signOutWayOutStands]): the shared code's line
    // for that end without "sign in again" ([LockedScreen.endLineBesideSignOut]).
    besideSignOut && locked.endLineBesideSignOut != null -> UiText.of(locked.endLineBesideSignOut!!)
    locked.endLine != null -> UiText.of(locked.endLine!!)
    !locked.signedOutByServer -> null
    else -> UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER)
}

/** The shared code's line that the account's keys are kept at the server ([LockedScreen.keysAtServerLine]), as handed. */
internal fun lockKeysAtServerLine(locked: LockedScreen): UiText? = locked.keysAtServerLine?.let { UiText.of(it) }

/** What an unlock's answer says on the lock screen: STALE in words of its own, the rest as every intent says it. */
internal fun unlockWords(r: VaultUnlockResult, retryAfterSeconds: Int): UiText? =
    when (r) {
        VaultUnlockResult.STALE -> UiText.ph(Placeholder.UNLOCK_STALE)
        // The lock screen's most common answer, said in words rather than as the result's name.
        VaultUnlockResult.WRONG_PASSWORD -> UiText.ph(Placeholder.UNLOCK_WRONG_PASSWORD)
        else -> UiText.forResult(r, retryAfterSeconds)
    }

/**
 * The line above an open vault whose server is stopped on this device: a session the server ended says so
 * ([TrustModel.openedSignedOutByServer]); anything else is a fork, unless the server's card already says it.
 */
internal fun stoppedLine(model: TrustModel, s: AppSnapshot, account: AccountSnapshot): UiText? = when {
    !account.serverStopped -> null
    model.openedSignedOutByServer(s) -> account.endLine?.let { UiText.of(it) } ?: UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER_OPEN)
    s.instance?.card is InstanceCardState.Stopped -> null
    else -> UiText.of(CopyKey.CARD_FORK)
}

/**
 * The open vault's one quiet line while live updates are not connected ([AccountSnapshot.liveUpdates]'s line, which the
 * shared code clears the moment a socket opens); null otherwise. Never a dialog, an error or a badge.
 */
internal fun liveUpdatesLine(account: AccountSnapshot): UiText? = account.liveUpdates.line?.let { UiText.of(it) }

/** The lock screen's title:[CopyKey.MASTER_PASSWORD_FOR] for the stored account. */
internal fun lockTitle(locked: LockedScreen): UiText =
    locked.prompt.title?.let { UiText.of(it) } ?: UiText.Plain(fillCopy(CopyKey.MASTER_PASSWORD_FOR, "", locked.prompt.instance.name, locked.prompt.instance.origin))

private fun submitUnlock(model: TrustModel, locked: LockedScreen, password: String, clear: () -> Unit) {
    model.runSaying({ unlock(locked, password) }, { unlockWords(it, model.api.retryAfterSeconds()) }) { clear() }
}

/**
 * The signed-in account (IF-3 author note 1: UNLOCKED shows `account`). The vault's items are drawn by the
 * vault's own screens. Around them:
 * the account and its server, the server's card, what waits for an answer, the shared vaults, lock and sign out.
 */
@Composable
internal fun AccountShell(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    account.kit?.let { return KitScreenView(model, s, it) }
    // A device link from this phone is a screen of its own while it runs or until its end is dismissed; leaving it cancels it.
    account.deviceLink?.let { return DeviceLinkHostPage(model, s, account, it) }
    // A link someone sent, once opened, is answered first, on a screen of its own (§12.1, "its join screen").
    account.opened?.let { return OpenedLinkPage(model, s, it) }
    // The old app's structure: the vault is the home screen; sharing (shared vaults, people, links) and settings are
    // behind the icons in the top bar, and Back returns home. A new session starts at home, unless a two-step set-up
    // waits on its confirm step (the person left to add the key to an authenticator): then it starts on Settings, and
    // a set-up the engine brings back after the unlock opens Settings too.
    val firstPage = LocalFirstPage.current
    var page by rememberSaveable(account.accountId) { mutableStateOf(firstPage ?: landingPage(account)) }
    val enrolment = account.twoStep?.enrolment
    LaunchedEffect(enrolment) { if (enrolment != null) page = SignedInPage.SETTINGS }
    // Sharing's page for one shared vault (the current app's vault settings): Back and the top bar's arrow return to
    // the list first. A vault gone from the list (deleted, left, revoked elsewhere) falls back to the list.
    val firstSharingVault = LocalFirstSharingVault.current
    var sharingVaultId by rememberSaveable(account.accountId) { mutableStateOf(firstSharingVault) }
    LaunchedEffect(page) { if (page != SignedInPage.SHARING) sharingVaultId = null }
    val sharingVault = sharingVaultShown(account, sharingVaultId)
    // A comparison of codes is a screen of its own over whichever page opened it (the prompt that a contact's key
    // changed stands on every page; People opens it too), so the person who chose to compare sees the codes at once.
    // Back closes it and returns to that page, which is remembered above.
    account.comparing?.let { return ComparePage(model, s, it) }
    ActiveBackHandler(model, enabled = page != SignedInPage.VAULT) {
        if (page == SignedInPage.SHARING && sharingVault != null) sharingVaultId = null else page = SignedInPage.VAULT
    }
    // The current app's structure: each page has its top bar (the vault's with its actions, Sharing's and Settings'
    // with the way back), and what needs the person wherever they are stands at the top of every page's body.
    val header: @Composable () -> Unit = { AccountLines(model, s, account) }
    when (page) {
        SignedInPage.VAULT -> VaultItemsSection(model, header = {
            header()
            liveUpdatesLine(account)?.let { Quiet(it) }
            // A vault read-only on this device while its deletion by "Move everything" waits: the line above the items too.
            for (line in readOnlyVaultLines(account)) Quiet(line)
        }) { page = it }
        SignedInPage.SHARING -> if (sharingVault != null) {
            // The current app's vault settings: the vault's name in the top bar, its page in one card.
            PageScaffold(UiText.Plain(vaultRowName(sharingVault)), onBack = { sharingVaultId = null }) {
                header()
                SettingsCard { SharedVaultSettings(model, s, account, sharingVault) }
            }
        } else PageScaffold(UiText.ph(Placeholder.SHARING), onBack = { page = SignedInPage.VAULT }) {
            header()
            // The current app's Sharing: one full-width card per section, the vaults first.
            SettingsCard { SharedVaultsSection(model, s, account) { sharingVaultId = it } }
            SettingsCard { PeopleSection(model, s, account) }
            SettingsCard { LinksSection(model, s, account) }
            RecentlyDeletedVaultsSection(model)
        }
        SignedInPage.SETTINGS -> PageScaffold(UiText.ph(Placeholder.SETTINGS), onBack = { page = SignedInPage.VAULT }) {
            header()
            AccountSettingsPage(model, s, account)
        }
    }
}

/** What needs the person wherever they are: the server's card, a fork, what an intent answered, prompts. */
@Composable
private fun AccountLines(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    run {
        s.instance?.let { InstanceCard(model, s, it) }
        stoppedLine(model, s, account)?.let { Say(it, color = MaterialTheme.colorScheme.error) }
        SaidHere(model, s)
        // A link for the server this account is on was not used (NOT_USABLE_SIGNED_IN): the owner's words (entry 7), in
        // place, until dismissed.
        account.inviteNotUsed?.let { line ->
            Say(UiText.of(line))
            Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.act { links.dismissOpened() } }
        }
        account.kitAfterMove?.let { KitAfterMoveCard(model, s, it) }
        for (move in account.unfinishedMoves) UnfinishedMoveOffer(model, s, move)
        for (n in account.movesStoredOutside) MoveStoredOutsideNotice(model, s, n)
        for (n in account.moveNotes) MoveNoteView(model, s, n)
        // What became of a change to a shared vault this device let go of or sent again, until the person dismisses it.
        for (n in account.waitingNotices) WaitingNoticeView(model, s, n)
        PromptsSection(model, s, account.prompts)
    }
}

/**
 * What a "Move everything" run left to say ([AccountSnapshot.moveNotes]): each line as the shared code hands it, the
 * member it names right after the line that names them (as the shared code names that person now), and a dismiss, the
 * only thing that takes it away: the shared code keeps it until then, across a lock and a restart.
 */
@Composable
internal fun MoveNoteView(model: TrustModel, s: AppSnapshot, note: io.silencelen.andvari.core.app.MoveNote) {
    for (line in moveNoteLines(note)) Say(line)
    Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.dismissMoveNote(note) }
}

/** The note's lines that say the member the move removes still holds a half-made vault: the kept one, and the frozen one. */
private val MEMBER_HOLDS_LINES = setOf(
    io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS,
    io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS,
)

/**
 * A move's note's lines in order; after a line that the member the move removes still holds a half-made vault
 * ([MEMBER_HOLDS_LINES]), the member it is about ([personLine], as everywhere else a member is shown). Nothing is
 * worded, added or dropped here.
 */
internal fun moveNoteLines(note: io.silencelen.andvari.core.app.MoveNote): List<UiText> = note.lines.flatMap { line ->
    val member = note.member?.takeIf { line.key in MEMBER_HOLDS_LINES }
    listOfNotNull(UiText.of(line), member?.let { personLine(it) })
}

/** The shared code's line for each vault that is read-only here while its deletion by a move waits, in the vaults' order. */
internal fun readOnlyVaultLines(account: AccountSnapshot): List<UiText> = account.vaults.mapNotNull { v -> v.readOnlyLine?.let { UiText.of(it) } }

/**
 * A move's deletion of its old vault that the server stored outside the move: the shared code's notice, as information
 * (it is no warning about the server), with "copy them" while there is something to copy, the line after a copy, and a
 * dismiss. The held copy stays in the holding area either way.
 */
@Composable
internal fun MoveStoredOutsideNotice(model: TrustModel, s: AppSnapshot, n: io.silencelen.andvari.core.app.MoveStoredNotice) {
    for (line in moveStoredLines(n)) Say(line)
    n.copiedLine?.let { Quiet(UiText.of(it)) }
    ButtonRow {
        if (n.canCopy && n.copiedLine == null) {
            Quieter(UiText.ph(Placeholder.MOVE_STORED_COPY), enabled = !s.busy) { model.run({ vaults.bringLateIntoMove(n) }) }
        }
        Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.act { vaults.dismissMoveStored(n) } }
    }
}

/**
 * The notice's own lines, as information: its line, then how many of the person's own waiting deletions the move carried
 * ([io.silencelen.andvari.core.app.MoveStoredNotice.carriedLine]) and how many it kept live in the new vault
 * ([io.silencelen.andvari.core.app.MoveStoredNotice.keptLine], now the usual outcome), each while the shared code gives it.
 */
internal fun moveStoredLines(n: io.silencelen.andvari.core.app.MoveStoredNotice): List<UiText> =
    listOfNotNull(UiText.of(n.line), n.carriedLine?.let { UiText.of(it) }, n.keptLine?.let { UiText.of(it) })

/** The signed-in area's pages, the vault first: it is the home screen. */
internal enum class SignedInPage { VAULT, SHARING, SETTINGS }

/**
 * The page a drawn screen opens on, for the screen images (ScreenImagesTest) only. Nothing in the app provides it, so on
 * a phone it is null and the account lands on [landingPage].
 */
internal val LocalFirstPage = androidx.compose.runtime.staticCompositionLocalOf<SignedInPage?> { null }

/** The shared vault whose page Sharing opens on, for the screen images only, as [LocalFirstPage]; null on a phone. */
internal val LocalFirstSharingVault = androidx.compose.runtime.staticCompositionLocalOf<String?> { null }

/** Settings: the account and its server, the settings sections, what is left of the old app, lock and sign out. */
@Composable
private fun AccountSettingsPage(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    run {
        Text(account.email, style = MaterialTheme.typography.titleMedium)
        Gap()
        // The current app's Settings opens with its identity card, then the server's, then appearance; the new app's
        // account ID stands where the identity code stood, and the server's card holds what the design adds (§12.3).
        SettingsCard { AccountIdCard(account) }
        s.instance?.let { SettingsCard { ServerSection(model, s, it) } }
        SettingsCard { AppearanceSection() }
        SettingsSections(model, s, account)
        s.oldData?.let { old ->
            if (!old.tellNow) {
                Say(UiText.Plain(Approved.OLD_DATA_NOT_REMOVED_TITLE))
                Quieter(UiText.Plain(Approved.OLD_DATA_NOT_REMOVED_TRY_AGAIN), enabled = !s.busy) { model.api.retryOldDataRemoval(old) }
            }
        }
        Gap()
        Second(UiText.ph(Placeholder.LOCK), enabled = !s.busy) { model.act { lock() } }
        SignOutButton(model, s)
    }
}

/**
 * Settings → the server (§12.3, §9.5 step 8): its name and origin, "Instance details" (the operator key's short form
 * and the pinned card's number), and "Forget this server", which removes the pin and this device's copy of the
 * account, behind a confirm. Under a fork the card above already offers it as the only way on.
 */
@Composable
private fun ServerSection(model: TrustModel, s: AppSnapshot, instance: io.silencelen.andvari.core.app.InstanceSnapshot) {
    SectionDivider()
    Say(Placeholder.SERVER_SECTION, style = sectionTitleStyle())
    // As the current app's: the address can be selected and copied.
    SelectionContainer { InstanceName(instance.label, MaterialTheme.typography.bodyLarge) }
    Say(Placeholder.OPERATOR_KEY, style = MaterialTheme.typography.labelSmall)
    Text(instance.details.operatorKeyShort.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
    // The card's number in its chain, said as what it is (it read as a bare "#0" after the key).
    Quiet(UiText.ph(Placeholder.CARD_SEQ, instance.details.cardSeq.toString()))
    PinnedCard0Hash(instance.details)
    if (instance.card !is InstanceCardState.Stopped && instance.card !is InstanceCardState.Damaged) {
        ForgetServerButton(model, s, instance, quiet = true)
    }
}

/**
 * The first card's hash as this phone pinned it, under its own label, for every kind of pin (design §12.3, "Instance
 * details"): what a person compares with the hash the server's operator gives. Nothing while no pin is held.
 */
@Composable
internal fun PinnedCard0Hash(details: io.silencelen.andvari.core.app.InstanceDetails) {
    val hash = details.pinnedCard0Hash
    if (hash.isEmpty()) return
    Say(details.pinnedCard0Label, style = MaterialTheme.typography.labelSmall)
    Text(hash.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
}

/** One line per prompt, from the API's copy where the design gives it (the answers come with the account slices). */
internal fun promptLine(p: AccountPrompt): UiText = when (p) {
    is AccountPrompt.IncomingVault -> UiText.of(p.line)
    is AccountPrompt.KeyChanged -> UiText.of(p.line)
    is AccountPrompt.NewPerson -> UiText.of(p.line)
    is AccountPrompt.PeopleList -> UiText.of(CopyKey.PEOPLE_TITLE)
    is AccountPrompt.RecoveryRequest -> UiText.of(p.line)
    is AccountPrompt.RecoveryKeyChanged -> UiText.of(p.title)
    is AccountPrompt.KeepOperatorRecovery -> UiText.of(p.question)
    is AccountPrompt.ConnectionNotMade -> UiText.ph(
        if (p.canRetry) Placeholder.CONNECTION_NOT_MADE_RETRY else Placeholder.CONNECTION_NOT_MADE,
        p.from,
        (UiText.forResult(p.why, 0) ?: UiText.ph(Placeholder.REFUSAL)).shown(),
    )
    is AccountPrompt.FinishServerSetup -> UiText.of(p.label)
}

/**
 * Sign out on this device (Settings and the lock screen), behind a confirm: it drops the session here and deletes this
 * phone's copy (IF-3 [io.silencelen.andvari.core.app.AppApi.signOut]); over changes not sent it says how many and asks
 * twice ([SignOutAsk]).
 */
@Composable
internal fun SignOutButton(model: TrustModel, s: AppSnapshot) {
    val drawn = LocalDrawnAsk.current
    val ask = drawn ?: remember(model) { model.signOutAsk() }
    Quieter(UiText.ph(Placeholder.SIGN_OUT), enabled = !s.busy) { ask.open() }
    LaunchedEffect(s) { ask.refresh() }
    // As the current app's "Sign out of this device?": its body says what signing out removes, then the lines about
    // changes not sent.
    SignOutConfirm(ask, s, UiText.ph(Placeholder.SIGN_OUT_CONFIRM), warning = null, dismiss = UiText.ph(Placeholder.STAY_SIGNED_IN), body = UiText.ph(Placeholder.SIGN_OUT_BODY))
}
