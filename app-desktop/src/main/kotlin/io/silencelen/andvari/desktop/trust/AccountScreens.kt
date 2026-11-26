package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InstanceDetails
import io.silencelen.andvari.core.app.InstanceSnapshot
import io.silencelen.andvari.core.app.LockedScreen

/**
 * The lock screen of a kept session (IF-3 author note 5): it names the account, the instance and its origin
 * (`locked.prompt.title`, §4.4), takes the master password, and nothing else is sent. The desktop has no quick unlock.
 * Under a fork the unlock still opens what this computer holds, read-only (§4.4 "a fork stops
 * traffic, not reading"); a damaged pin record blocks it, and the ways on are signing out and forgetting the server.
 */
@Composable
internal fun LockScreen(model: TrustModel, s: AppSnapshot, locked: LockedScreen) {
    var password by remember { mutableStateOf("") }
    val submit = {
        if (password.isNotEmpty() && !s.busy) {
            val typed = password
            model.run({ unlock(locked, typed) }) { password = "" }
        }
    }
    AuthColumn(verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Sigil()
        // Who is locked and on which server (§4.4), named once: one quiet line in the place and the tone of the current
        // app's address line under the head, the origin whole and monospaced in it; the field's label says what to type.
        LockNameLine(locked)
        Gap(20)
        UpdateNotice(model, s)
        // Under a server policy that keeps the account's keys at the server, every unlock asks it (none while it cannot be
        // reached, and nothing is removed then): the shared code's line, as handed.
        locked.keysAtServerLine?.let { Say(it) }
        // The server ended this session (design §4.4): the password still opens the copy here, read-only, except under a
        // policy that keeps the keys at the server, where nothing opens until the person signs in again; the shared code's
        // line for that end says so ([serverEndText]).
        if (locked.signedOutByServer) SignedOutByServerCard(model, s, offerSignOut = false)
        // A password change this copy could not follow: the previous password still opens it (core's flag).
        if (locked.previousPasswordOpensCopy) Say(UiText.ph(Placeholder.LOCKED_PREVIOUS_PASSWORD_OPENS))
        // Core's own record: a deletion was sent and no answer has said since whether it went through
        // (a check the session's end answered included: it cannot be told from a deletion, so nothing says "deleted");
        // kept across locks and restarts, cleared by the server's next answer for this account.
        if (locked.deletionOutcomeUnknown) Say(UiText.ph(Placeholder.DELETION_OUTCOME_UNKNOWN_LOCKED), color = MaterialTheme.colorScheme.error)
        // The shared code's offer to forget that account on this computer, in two steps (wherever it offers it).
        ForgetUnknownDeletionOffer(model, s)
        val instance = s.instance
        val unfinished = instance?.unfinishedMove
        // An unfinished move keeps the vault shut (the unlock answers SERVER_BLOCKED): its ways on come first.
        if (instance != null && unfinished != null) UnfinishedMoveCard(model, s, instance, unfinished)
        else when (instance?.card) {
            is InstanceCardState.Stopped -> {
                Say(CopyKey.CARD_FORK, color = MaterialTheme.colorScheme.error)
                ForgetServerButton(model, s, instance)
            }
            is InstanceCardState.Damaged -> {
                CardDamagedWords(instance.label.origin)
                ForgetServerButton(model, s, instance)
            }
            else -> {}
        }
        Gap()
        SecretField(UiText.ph(Placeholder.PASSWORD_FIELD), password, onEnter = { submit() }) { password = it }
        Main(UiText.ph(Placeholder.UNLOCK_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) { submit() }
        // "Unlocking" and what the unlock answered, in a slot of a fixed height: Sign out under it does not move.
        FixedSlot(UNLOCK_SAID_SLOT) {
            if (s.busy) Quiet(UiText.ph(Placeholder.UNLOCKING))
            SaidHere(model, s)
        }
        Gap()
        // Under a fork Sign out is not offered (design point 7): the card's "Forget this server" is the way on.
        if (instance?.card !is InstanceCardState.Stopped) SignOutButton(model, s)
    }
}

/**
 * The server ended this session ([LockedScreen.signedOutByServer], [AccountSnapshot.signedOutByServer]; design §4.4):
 * said by [serverEndText] (the copy here opens read-only, except where the shared code's line for the end says otherwise),
 * and "Sign in again" ([TrustModel.signInAgain]) takes it back for the same account and
 * sends what waited. Above an open vault, "Sign out" is offered beside it (on the lock screen it is there already).
 */
@Composable
internal fun SignedOutByServerCard(model: TrustModel, s: AppSnapshot, offerSignOut: Boolean) {
    Column(Modifier.padding(vertical = 8.dp)) {
        Say(serverEndText(s), color = MaterialTheme.colorScheme.error)
        Second(UiText.ph(Placeholder.SIGN_IN_AGAIN), enabled = !s.busy) { model.signInAgain() }
        if (offerSignOut) SignOutButton(model, s)
    }
}

/**
 * How that end is said: wherever the shared code hands its own line for it ([LockedScreen.endLine],
 * [AccountSnapshot.endLine]: a session this computer could not confirm in time, or the server's end while the account's
 * keys are kept at the server, where no password opens anything here), that line as handed, never "signed out by its
 * server" with a copy that opens; otherwise that. On the lock screen, beside a way out that signs this kept account out
 * ([lockSignOutNamed]), the shared code's line for the same end that does not say "sign in again".
 */
internal fun serverEndText(s: AppSnapshot): UiText =
    (s.locked?.let { lockEndLine(it, s) } ?: s.account?.endLine)?.let { UiText.of(it) }
        ?: UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER)

/** The lock screen's line for the session's end: [LockedScreen.endLineBesideSignOut] where [lockSignOutNamed], else [LockedScreen.endLine]. */
internal fun lockEndLine(locked: LockedScreen, s: AppSnapshot): CopyKey? =
    (if (lockSignOutNamed(locked, s)) locked.endLineBesideSignOut else null) ?: locked.endLine

/**
 * On the lock screen, the notice that a kit was wiped names this very kept session as what stands in the way, with its
 * sign-out as the way out ([io.silencelen.andvari.core.app.KitWipedNotice.wayOut], its mark equal to the lock screen's
 * [io.silencelen.andvari.core.app.MasterPasswordPrompt.keptMark], neither empty), and the lock screen offers "Sign out"
 * (not under a fork): a line about the session's end beside it must not tell the person to sign in again. The marks are
 * compared for equality only, never shown, logged or kept.
 */
internal fun lockSignOutNamed(locked: LockedScreen, s: AppSnapshot): Boolean {
    val notice = s.kitWiped ?: return false
    val mark = locked.prompt.keptMark
    return notice.wayOut == io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT &&
        mark.isNotEmpty() && notice.namedKept == mark && s.instance?.card !is InstanceCardState.Stopped
}

/** The lock screen's one naming line: [CopyKey.MASTER_PASSWORD_FOR] for the kept account. */
internal fun lockTitle(locked: LockedScreen): UiText =
    locked.prompt.title?.let { UiText.of(it) } ?: UiText.Plain(fillCopy(CopyKey.MASTER_PASSWORD_FOR, "", locked.prompt.instance.name, locked.prompt.instance.origin))

/**
 * Every line of the lock screen that names the account or its server, in order: [lockTitle], and the self-named mark
 * when nobody but the server vouches for its name (T-R8). The server's name and its origin are each in it once.
 */
internal fun lockNameLines(locked: LockedScreen): List<UiText> =
    listOfNotNull(lockTitle(locked), if (locked.prompt.instance.selfNamed) UiText.of(CopyKey.AS_THE_SERVER_NAMES_ITSELF) else null)

/** [lockNameLines], quiet and centred under the brand head; the origin in the line is monospaced, as everywhere. */
@Composable
private fun LockNameLine(locked: LockedScreen) {
    val tone = MaterialTheme.colorScheme.onSurfaceVariant
    val lines = lockNameLines(locked)
    val named = monospacedOrigin(lines.first().shown(), locked.prompt.instance.origin)
    Text(named, Modifier.fillMaxWidth().padding(top = 8.dp), color = tone, style = MaterialTheme.typography.bodyLarge.copy(textAlign = TextAlign.Center))
    for (line in lines.drop(1)) {
        Say(line, Modifier.fillMaxWidth().padding(top = 4.dp), MaterialTheme.typography.bodySmall.copy(textAlign = TextAlign.Center), tone)
    }
}

/**
 * The signed-in account (IF-3 author note 1: UNLOCKED shows `account`), in the old desktop app's structure: the vault
 * is the home page, and sharing and Settings are pages behind the top bar's icons, as the old app's toolbar had them
 * (with its sync button). A new unlock starts at home. Above every page stays what needs the person wherever they are:
 * the kit (a kit due shows first and alone), the server's card and a fork, what an intent answered, a new kit after a
 * move, a two-step set-up left on its confirm step, and the prompts, each answered in place ([PromptsSection]).
 *
 * - [SignedInPage.VAULT]: the vault's items ([VaultItemsSection]).
 * - [SignedInPage.SHARING]: shared vaults ([SharedVaultsSection]), people and the comparison codes ([PeopleSection]),
 *   links ([LinksSection]).
 * - [SignedInPage.SETTINGS]: the account, keeping the sign-in, the Settings sections ([SettingsSections]), the
 *   server, lock and sign out.
 */
@Composable
internal fun AccountShell(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    account.kit?.let { return KitScreenView(model, s, it) }
    val unlocks by model.unlocks.collectAsState()
    // Keyed by the unlock: every unlock starts at home, and the vault composed again under an open window (the switch
    // "keep me signed in" turned off) leaves the person on the page they were on.
    var page by remember(account.accountId, unlocks) { mutableStateOf(SignedInPage.VAULT) }
    // The menu's Import opens on the vault page.
    val importWanted by model.importRequested.collectAsState()
    if (importWanted && page != SignedInPage.VAULT) page = SignedInPage.VAULT
    // Settings' backup card opens its panel over the vault: the vault page shows it.
    val content by model.content.collectAsState()
    val exporting = content?.let { it.states.collectAsState().value.exporting != null } == true
    if (exporting && page != SignedInPage.VAULT) page = SignedInPage.VAULT
    // This build too old for the session's server: the vault stays open and readable, and nothing offers a save.
    CompositionLocalProvider(LocalSavesHeld provides model.updateRequiredOn(s)) {
        SignedInPages(model, s, account, page) { page = it }
    }
    // The name this account's links carry, asked for over whichever page a link road started on ([LinkNameAsk]).
    LinkNameWindow(model, s)
}

/**
 * The server is stopped on this computer (a fork, §4.4): the design's point 7 on the desktop. The only actions are
 * reading, export and "Forget this server" (with its question); Sign out, the Sharing page, the Settings page, sync and
 * the prompts are not offered. Locking stays (the menu's Lock and Ctrl+L): it sends nothing and closes the keys.
 */
internal fun forked(s: AppSnapshot): Boolean = s.instance?.card is InstanceCardState.Stopped || s.account?.serverStopped == true

@Composable
private fun SignedInPages(model: TrustModel, s: AppSnapshot, account: AccountSnapshot, wanted: SignedInPage, go: (SignedInPage) -> Unit) {
    val fork = forked(s)
    val operator = model.operator.available(s)
    val page = if (fork || (wanted == SignedInPage.OPERATOR && !operator)) SignedInPage.VAULT else wanted
    SignedInColumn {
        when (page) {
            // The current app's vault window: its toolbar over a rule, then the list (which scrolls under the toolbar,
            // with what needs the person at its top).
            SignedInPage.VAULT -> {
                SignedInTopBar(model, fork, operator, go)
                HorizontalDivider()
                VaultItemsSection(model) {
                    AttentionArea(model, s, account, page, fork, go)
                    // Live updates not connected: one quiet line, nothing to do (core's line; null while connected or not running).
                    account.liveUpdates.line?.let { Quiet(UiText.of(it)) }
                }
            }
            // Sharing, Settings and the console are pages of their own, as the current app's Settings and Sharing are:
            // "back" and a large title, then their sections as cards.
            // What an intent answered stands at the foot of the window over the page, not above its cards: an answer to
            // a button in a lower card neither pushes the cards down under the pointer nor lands out of sight.
            else -> Box(Modifier.fillMaxSize()) {
                model.said.collectAsState().value
                val answered = model.saidOn(s) != null
                PageColumn {
                    PageHeader(UiText.ph(pageTitle(page))) { go(SignedInPage.VAULT) }
                    AttentionArea(model, s, account, page, fork, go, saidInPlace = false)
                    when (page) {
                        SignedInPage.SHARING -> {
                            SectionCard { SharedVaultsSection(model, s, account) }
                            SectionCard { PeopleSection(model, s, account) }
                            SectionCard { LinksSection(model, s, account) }
                        }
                        SignedInPage.SETTINGS -> AccountSettingsPage(model, s, account)
                        SignedInPage.OPERATOR -> OperatorPage(model, s)
                        SignedInPage.VAULT -> {}
                    }
                    // Room at the end, so the last card scrolls clear of the bar.
                    if (answered) Spacer(Modifier.height(PAGE_SAID_ROOM))
                }
                Column(Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(horizontal = 16.dp)) { SaidHere(model, s) }
            }
        }
    }
}

/** The room left under a page's last card while the error bar stands over the foot of the window. */
internal val PAGE_SAID_ROOM = 120.dp

/** The title of a page of its own. */
internal fun pageTitle(page: SignedInPage): Placeholder = when (page) {
    SignedInPage.SHARING -> Placeholder.SHARING
    SignedInPage.SETTINGS -> Placeholder.SETTINGS
    SignedInPage.OPERATOR -> Placeholder.OPERATOR_CONSOLE
    SignedInPage.VAULT -> Placeholder.VAULT_ITEMS
}

/**
 * What needs the person wherever they are, above every signed-in page (the current app's attention area): the update,
 * the server's card and a fork, a session the server ended, what an intent answered, a new kit after a move, a two-step
 * set-up left on its confirm step, and the prompts, each answered in place ([PromptsSection]).
 */
@Composable
private fun AttentionArea(model: TrustModel, s: AppSnapshot, account: AccountSnapshot, page: SignedInPage, fork: Boolean, go: (SignedInPage) -> Unit, saidInPlace: Boolean = true) {
    UpdateNotice(model, s)
    s.instance?.let { InstanceCard(model, s, it) }
    if (account.signedOutByServer) {
        // Read-only from the copy here; the ways on are signing in again and signing out (which deletes the copy).
        SignedOutByServerCard(model, s, offerSignOut = true)
    } else if (account.serverStopped && s.instance?.card !is InstanceCardState.Stopped) {
        Say(CopyKey.CARD_FORK, color = MaterialTheme.colorScheme.error)
        s.instance?.let { ForgetServerButton(model, s, it) }
    }
    if (saidInPlace) SaidHere(model, s)
    // The one line after a sign-in about this computer's copy (it was sealed under another master password and now
    // follows the server's): once, until dismissed; a lock clears it too.
    account.signInNotice?.let { NoticeBar(UiText.of(it)) { model.quietly { model.api.dismissSignInNotice() } } }
    // What a lock cut short last time is the shared code's own notice, with the vault's other notices (VaultItemsList).
    if (!fork) {
        account.kitAfterMove?.let { KitAfterMoveCard(model, s, it) }
        // A move's deletion of its old vault that the server stored outside the move: each notice until dismissed.
        for (notice in account.movesStoredOutside) MoveStoredCard(model, s, notice)
        // What a move left to say (a half-made vault kept, earlier copies kept beside newer ones): each until dismissed.
        for (note in account.moveNotes) MoveNoteCard(model, s, note)
        // What became of a change to a shared vault that this device let go of or sent again: each until dismissed.
        for (notice in account.waitingNotices) WaitingNoticeCard(model, s, notice)
        // A move of everything out of a vault that this computer started and did not finish: offered until put off.
        for (move in account.unfinishedMoves) UnfinishedMoveOffer(model, s, move) { go(SignedInPage.SHARING) }
        // A two-step set-up found open on its confirm step (after an unlock, say) waits on the Settings page.
        if (page != SignedInPage.SETTINGS && twoStepWaiting(account)) {
            Say(Placeholder.TWO_STEP_WAITING)
            Quieter(UiText.ph(Placeholder.SETTINGS)) { go(SignedInPage.SETTINGS) }
        }
        PromptsSection(model, s, account.prompts, openSharing = { go(SignedInPage.SHARING) }) {
            go(SignedInPage.SETTINGS)
            if (account.recovery == null) model.run({ recovery.openRecovery() })
        }
    }
}

/**
 * The signed-in area's pages, the vault first: it is the home page. [OPERATOR] is the operator's console, which only the
 * operator account has ([OperatorModel.available]); for any other account it is never offered and shows nothing.
 */
internal enum class SignedInPage { VAULT, SHARING, SETTINGS, OPERATOR }

/** A two-step enrolment is open and waits for its first code. */
internal fun twoStepWaiting(account: AccountSnapshot): Boolean = account.twoStep?.enrolment != null

/** The current desktop app's signed-in screens are one column of at most 760 dp, top-centred, the toolbar included. */
internal val SIGNED_IN_MAX_WIDTH = 760.dp

@Composable
private fun SignedInColumn(content: @Composable ColumnScope.() -> Unit) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = SIGNED_IN_MAX_WIDTH).fillMaxSize(), content = content)
    }
}

/**
 * The vault's toolbar, as the current app's: the name, then import, sharing, trash, vault health, Settings, the console
 * (the operator account's alone, §9.1), sync (a spinner in its place while a sync runs) and lock. Under a fork only the
 * name and lock are left: the vault is the only page and nothing syncs or is sent (design point 7).
 */
@Composable
private fun SignedInTopBar(model: TrustModel, fork: Boolean, operator: Boolean, go: (SignedInPage) -> Unit) {
    val content by model.content.collectAsState()
    val scope = rememberWorkScope()
    var answer by remember(content) { mutableStateOf<String?>(null) }
    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        // One line, never broken a letter at a time (found at a width under the window's floor, where no window manager holds it).
        Text("andvari", Modifier.weight(1f), style = MaterialTheme.typography.titleLarge, maxLines = 1, softWrap = false)
        val c = content
        if (!fork && c != null) {
            val state by c.states.collectAsState()
            // The menu's Import and this icon open the same file dialog ([ImportRequests]); only where a save is possible.
            if (canSave(state)) BarIcon(Icons.Default.FileUpload, Placeholder.IMPORT_PASSWORDS, enabled = !state.busy) { model.requestImport() }
            BarIcon(Icons.Default.Group, Placeholder.SHARING) { go(SignedInPage.SHARING) }
            BarIcon(Icons.Default.Delete, Placeholder.TRASH, enabled = !state.busy) { scope.launch { answer = sentence(c.openTrash()) } }
            BarIcon(Icons.Default.HealthAndSafety, Placeholder.HEALTH, enabled = !state.busy) { c.openHealth() }
            BarIcon(Icons.Default.Settings, Placeholder.SETTINGS) { go(SignedInPage.SETTINGS) }
            if (operator) BarIcon(Icons.Default.AdminPanelSettings, Placeholder.OPERATOR_CONSOLE) { go(SignedInPage.OPERATOR) }
            if (state.syncing) {
                Box(Modifier.size(BAR_ICON), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(
                        Modifier.size(18.dp).semantics { contentDescription = UiText.ph(Placeholder.SYNC_NOW).shown(); stateDescription = "syncing" },
                        strokeWidth = 2.dp,
                    )
                }
            } else {
                BarIcon(Icons.Default.Refresh, Placeholder.SYNC_NOW, enabled = !state.busy) { model.syncNow() }
            }
        }
        BarIcon(Icons.Default.Lock, Placeholder.LOCK) { model.lockNow() }
    }
    answer?.let { Say(UiText.Plain(it), Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.error) }
}

/** A toolbar icon: 44 dp, so all of them and the name fit the window's 480 dp floor, the console's included. */
internal val BAR_ICON = 44.dp

@Composable
private fun BarIcon(icon: ImageVector, label: Placeholder, enabled: Boolean = true, onClick: () -> Unit) {
    IconButton(onClick = guarded(onClick = onClick), enabled = enabled, modifier = Modifier.size(BAR_ICON)) {
        Icon(icon, UiText.ph(label).shown())
    }
}

/**
 * Settings, as the current app's page: one card per section. This account (its address, its account ID, keeping the
 * sign-in), the settings sections ([SettingsSections]), the backup and exports, the server, what is left of the old
 * app, then lock and sign out.
 */
@Composable
private fun AccountSettingsPage(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    SectionCard {
        SectionTitle(Placeholder.ACCOUNT_TITLE)
        Text(account.email, style = MaterialTheme.typography.titleMedium)
        Text(fillCopy(CopyKey.KIT_ACCOUNT_ID, account.accountId.chunked(4).joinToString(" ")), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
        KeepSignInTick(model, s)
    }
    SettingsSections(model, s, account)
    BackupSection(model)
    s.instance?.let { SectionCard { ServerSection(model, s, it) } }
    OldDataSettingsLine(model, s)
    Gap()
    Second(UiText.ph(Placeholder.LOCK), enabled = !s.busy) { model.lockNow() }
    SignOutButton(model, s)
}

/** The sign-in and the offline copy stay on disk only while this is ticked. Off by default. */
@Composable
internal fun KeepSignInTick(model: TrustModel, s: AppSnapshot) {
    val keep by model.keepSignIn.collectAsState()
    val unknown by model.keepUnknown.collectAsState()
    // A policy that forbids an offline copy wins over the switch; an unreadable setting is answered above first.
    val forbidden = model.keepForbidden(s)
    Tick(UiText.ph(Placeholder.KEEP_SIGN_IN), keep, enabled = !s.busy && !unknown && (keep || !forbidden)) { model.setKeepSignIn(it) }
    // Said once the switch is off: while the shared code still removes the copy (≤ a minute) the switch stays as it was
    // and the vault says the removal's own line.
    if (forbidden && !keep) Quiet(UiText.ph(Placeholder.KEEP_FORBIDDEN))
}

/**
 * The server (§12.3, §9.5 step 8): its name and origin, the operator key's short form and the pinned card's number,
 * and "Forget this server", which removes the pin and this computer's copy of the account, behind a confirm. Under a
 * fork the card above already offers it as the only way on.
 */
@Composable
private fun ServerSection(model: TrustModel, s: AppSnapshot, instance: InstanceSnapshot) {
    var confirm by remember { mutableStateOf(false) }
    SectionTitle(Placeholder.SERVER_SECTION)
    InstanceName(instance.label, MaterialTheme.typography.bodyLarge)
    Say(Placeholder.OPERATOR_KEY, style = MaterialTheme.typography.labelSmall)
    Text(instance.details.operatorKeyShort.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
    Text("#${instance.details.cardSeq}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    PinnedCard0Hash(instance.details)
    if (instance.card !is InstanceCardState.Stopped && instance.card !is InstanceCardState.Damaged) {
        Quieter(UiText.of(CopyKey.FORGET_THIS_SERVER), enabled = !s.busy) { confirm = true }
    }
    // The same question as every card's "Forget this server".
    if (confirm) ForgetServerQuestion(model, instance) { confirm = false }
}

/**
 * The hash of the server's first card as this computer pinned it, under its label (the shared code's line), for every
 * kind of pin: what the person compares with the hash the operator gives. Nothing while no pin is held.
 */
@Composable
internal fun PinnedCard0Hash(details: InstanceDetails) {
    if (details.pinnedCard0Hash.isEmpty()) return
    Say(details.pinnedCard0Label, style = MaterialTheme.typography.labelSmall)
    // In groups of four, wrapped, as the operator key above it: the whole of it is read and compared.
    Text(details.pinnedCard0Hash.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
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
    is AccountPrompt.ConnectionNotMade -> UiText.ph(if (p.canRetry) Placeholder.CONNECTION_NOT_MADE_RETRY else Placeholder.CONNECTION_NOT_MADE_SPENT, p.from)
    is AccountPrompt.FinishServerSetup -> UiText.of(p.label)
}

/** Sign out on this computer, behind a confirm: it drops the session here ([io.silencelen.andvari.core.app.AppApi.signOut]). */
@Composable
internal fun SignOutButton(model: TrustModel, s: AppSnapshot) {
    var confirm by remember { mutableStateOf(false) }
    Quieter(UiText.ph(Placeholder.SIGN_OUT), enabled = !s.busy) { confirm = true }
    if (confirm) SignOutQuestion(model, null, s) { confirm = false }
}
