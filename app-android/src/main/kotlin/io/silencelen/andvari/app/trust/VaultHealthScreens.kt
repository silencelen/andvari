package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.material3.Checkbox
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import io.silencelen.andvari.core.app.HealthTilesView
import io.silencelen.andvari.app.ExternalExcursion
import io.silencelen.andvari.app.copyToClipboard
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CheckRunView
import io.silencelen.andvari.core.app.DuplicateClusterView
import io.silencelen.andvari.core.app.HealthView
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.ItemText
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.app.launchOvertakable

/**
 * Vault health: the tiles, the passwords with their strength, reuse and breaches, the breach check, the duplicate
 * clusters with merge, keep one and "not duplicates" (each behind the content's own confirmation where it gives one)
 * and the groups marked "not duplicates" with Put back; staleness with the check run, its four verdicts, skip and stop,
 * snoozing shown on request and Unsnooze; and the two offers a verdict raises (a gone login to the trash, a refused
 * password to open or to give a new one). Every verdict is the person's: nothing here signs in or changes a password.
 * [onOpenItem] opens an item from the bad-password offer: its detail, or its editor with a new password unsaved.
 */
@Composable
internal fun HealthPanel(model: TrustModel, c: VaultContent, state: ContentState, h: HealthView, onOpenItem: (itemId: String, generate: Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    var answer by remember(c) { mutableStateOf<String?>(null) }
    fun said(r: ActionResult) {
        answer = when (r) {
            is ActionResult.Failed -> r.message
            is ActionResult.NotDone -> r.message
            else -> null
        }
    }
    val canWrite = canSave(state) && !state.busy
    // The title and the way back are in the page's top bar, as the current app's "Vault health".
    h.message?.let {
        Say(UiText.Plain(it))
        Quieter(UiText.ph(Placeholder.CLOSE)) { c.dismissHealthMessage() }
    }
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    h.offerDelete?.let { o ->
        Say(Placeholder.HEALTH_OFFER_GONE, o.name)
        ButtonRow {
            Quieter(UiText.ph(Placeholder.HEALTH_KEEP_IT)) { c.keepGoneLogin() }
            Quieter(UiText.ph(Placeholder.HEALTH_TO_TRASH), enabled = canWrite) { scope.launchOvertakable { said(c.trashGoneLogin()) } }
        }
    }
    h.offerBad?.let { o ->
        Say(Placeholder.HEALTH_OFFER_BAD, o.name)
        ButtonRow {
            Quieter(UiText.ph(Placeholder.LATER)) { c.answerBadOffer(false) }
            Quieter(UiText.ph(Placeholder.HEALTH_OPEN_ITEM)) {
                c.answerBadOffer(true)
                onOpenItem(o.itemId, false)
            }
            Quieter(UiText.ph(Placeholder.HEALTH_NEW_PASSWORD), enabled = canWrite) {
                c.answerBadOffer(true)
                onOpenItem(o.itemId, true)
            }
        }
    }
    h.run?.let { CheckRunPanel(model, c, state, it, canWrite) { r -> said(r) } }
    val t = h.tiles
    HealthTiles(healthTiles(t))
    h.scan?.let { Say(Placeholder.HEALTH_CHECKING, it.done.toString(), it.total.toString()) }
    ButtonRow {
        Quieter(UiText.ph(Placeholder.HEALTH_CHECK_BREACHES), enabled = !state.busy && h.scan == null) { scope.launchOvertakable { said(c.checkBreaches()) } }
        Quieter(UiText.ph(Placeholder.HEALTH_REFRESH), enabled = !state.busy) { c.refreshHealth() }
    }
    // The current app's three tabs under the tiles: Passwords, Duplicates and Staleness, one list on show at a time.
    val drawnTab = LocalFirstVaultView.current?.healthTab
    var tab by rememberSaveable { mutableStateOf(drawnTab ?: HealthTab.PASSWORDS) }
    TabRow(selectedTabIndex = tab.ordinal) {
        for (t in HealthTab.entries) {
            Tab(selected = tab == t, onClick = { tab = t }, text = { Say(UiText.ph(t.label)) })
        }
    }
    when (tab) {
        HealthTab.PASSWORDS -> PasswordsTab(h)
        HealthTab.DUPLICATES -> DuplicatesTab(c, h, canWrite) { r -> said(r) }
        HealthTab.STALENESS -> StalenessList(c, state, h, canWrite) { r -> said(r) }
    }
}

/** Vault health's tabs, in the current app's order (HealthScreen's TABS). */
internal enum class HealthTab(val label: Placeholder) {
    PASSWORDS(Placeholder.HEALTH_TAB_PASSWORDS),
    DUPLICATES(Placeholder.HEALTH_TAB_DUPLICATES),
    STALENESS(Placeholder.HEALTH_TAB_STALENESS),
}

/** The Duplicates tab: each cluster with merge, keep one and "not duplicates", then the groups marked "not duplicates". */
@Composable
private fun DuplicatesTab(c: VaultContent, h: HealthView, canWrite: Boolean, said: (ActionResult) -> Unit) {
    val scope = rememberCoroutineScope()
    h.duplicates.forEach { DuplicateCluster(c, it, canWrite) { r -> said(r) } }
    if (h.notDuplicates.isNotEmpty()) {
        Say(Placeholder.HEALTH_MARKED_NOT_DUPLICATES, style = MaterialTheme.typography.labelMedium)
        h.notDuplicates.forEach { d ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(ItemText.label(d.sites) + "  ·  " + d.members.joinToString(", ") { ItemText.label(it.name) }, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                Quieter(UiText.ph(Placeholder.HEALTH_PUT_BACK), enabled = canWrite) { scope.launchOvertakable { said(c.restoreDuplicates(d.signature)) } }
            }
        }
    }
}

/** The Passwords tab: each login with its strength, reuse and breaches. */
@Composable
private fun PasswordsTab(h: HealthView) {
    h.passwords.forEach { p ->
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text(ItemText.label(p.name), style = MaterialTheme.typography.bodyLarge)
            val marks = listOfNotNull(
                p.strength,
                // [reused] counts the OTHER logins with this exact password.
                counted(p.reused.toLong(), Placeholder.HEALTH_REUSED, Placeholder.HEALTH_REUSED_ONE).shown().takeIf { p.reused > 0 },
                p.breaches?.takeIf { it > 0 }?.let { counted(it.toLong(), Placeholder.HEALTH_BREACHED, Placeholder.HEALTH_BREACHED_ONE).shown() },
            )
            Text(marks.joinToString("  ·  "), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** One of the summary's tiles: its label, its number, and whether the number is bad (null: no verdict, neutral). */
internal class HealthTile(val label: Placeholder, val value: String, val bad: Boolean?, val hint: String? = null)

/**
 * The summary as the current app's seven tiles, in its order. A count above nought is bad; nought is good; breaches
 * never checked ("?") and a breach count the content qualifies ([HealthTilesView.breachedHint], which the Breached
 * tile says under its label, as the current app's does) are neither.
 */
internal fun healthTiles(t: io.silencelen.andvari.core.app.HealthTilesView): List<HealthTile> {
    fun n(label: Placeholder, v: Int, judged: Boolean = true) = HealthTile(label, v.toString(), if (judged) v > 0 else null)
    val breached = t.breached
    return listOf(
        n(Placeholder.HEALTH_TILE_LOGINS, t.logins, judged = false),
        n(Placeholder.HEALTH_TILE_WEAK, t.weak),
        n(Placeholder.HEALTH_TILE_REUSED, t.reused),
        HealthTile(
            Placeholder.HEALTH_TILE_BREACHED, breached?.toString() ?: "?",
            when {
                breached == null -> null
                breached > 0 -> true
                t.breachedHint != null -> null
                else -> false
            },
            t.breachedHint,
        ),
        n(Placeholder.HEALTH_TILE_DUPLICATES, t.duplicates),
        n(Placeholder.HEALTH_TILE_UNCHECKED, t.unchecked),
        n(Placeholder.HEALTH_TILE_FAILING, t.failing),
    )
}

/**
 * The current app's tiles: small cards in the surface-variant tone that wrap onto the next line, each with its number
 * in the title size (red when bad, the primary tone when good, quiet without a verdict) over its label; one
 * announcement per tile ("label: number"), so the tone is never the only signal.
 */
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun HealthTiles(tiles: List<HealthTile>) {
    androidx.compose.foundation.layout.FlowRow(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        for (tile in tiles) {
            val tone = when (tile.bad) {
                null -> MaterialTheme.colorScheme.onSurfaceVariant
                true -> MaterialTheme.colorScheme.error
                false -> MaterialTheme.colorScheme.primary
            }
            val label = UiText.ph(tile.label)
            androidx.compose.material3.Card(
                colors = androidx.compose.material3.CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                modifier = Modifier.clearAndSetSemantics {
                    contentDescription = label.shown() + ": " + tile.value + (tile.hint?.let { " · $it" } ?: "")
                },
            ) {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                    Text(tile.value, style = MaterialTheme.typography.titleMedium, color = tone)
                    Say(label, style = MaterialTheme.typography.labelSmall)
                    tile.hint?.let { Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }
    }
}

/**
 * Staleness: each login with where it stands and its dates, worst first; snoozed ones only on request (the counts at the
 * top never change with it), each with Unsnooze; the check run over all of them or the never-checked only, or one login.
 */
@Composable
private fun StalenessList(c: VaultContent, state: ContentState, h: HealthView, canWrite: Boolean, said: (ActionResult) -> Unit) {
    val scope = rememberCoroutineScope()
    Say(Placeholder.HEALTH_STALENESS, style = MaterialTheme.typography.labelMedium)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = h.showSnoozed, onCheckedChange = { c.setHealthShowSnoozed(it) })
        Say(Placeholder.HEALTH_SHOW_SNOOZED)
    }
    if (h.allSnoozed) Say(Placeholder.HEALTH_ALL_SNOOZED)
    if (h.run == null && h.staleness.isNotEmpty()) {
        ButtonRow {
            Quieter(UiText.ph(Placeholder.HEALTH_RUN_ALL), enabled = canWrite) { c.startCheckRun(false) }
            if (h.staleness.any { it.neverChecked }) {
                Quieter(UiText.ph(Placeholder.HEALTH_RUN_NEVER_CHECKED), enabled = canWrite) { c.startCheckRun(true) }
            }
        }
    }
    h.staleness.forEach { s ->
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text(nameLine(s.name, s.username), style = MaterialTheme.typography.bodyLarge)
            Text(s.state, style = MaterialTheme.typography.bodySmall, color = if (s.failing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            if (s.dates.isNotEmpty()) Text(s.dates, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            ButtonRow {
                if (h.run == null) Quieter(UiText.ph(Placeholder.HEALTH_CHECK_THIS), enabled = canWrite) { c.checkLogin(s.itemId) }
                if (s.snoozed) Quieter(UiText.ph(Placeholder.HEALTH_UNSNOOZE), enabled = canWrite && !state.busy) { scope.launchOvertakable { said(c.unsnoozeLogin(s.itemId)) } }
            }
        }
    }
}

/**
 * The check run on one login: its place in the run, the site to sign in at (opened in a Custom Tab, an excursion the
 * lock lets pass), its password to copy, and what happened, in the person's own verdict. Skip writes nothing; Stop
 * ends the run. Each carries the same weight as a verdict.
 */
@Composable
private fun CheckRunPanel(model: TrustModel, c: VaultContent, state: ContentState, r: CheckRunView, canWrite: Boolean, said: (ActionResult) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Say(Placeholder.HEALTH_RUN_POSITION, r.position.toString(), r.total.toString(), style = MaterialTheme.typography.labelMedium)
        Text(nameLine(r.name, r.username), style = MaterialTheme.typography.bodyLarge)
        r.site?.let { site ->
            Text(ItemText.label(site), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
            if (carriesUserInfo(site)) {
                Say(UiText.ph(Placeholder.OPEN_SITE_REFUSED), style = MaterialTheme.typography.bodySmall)
            } else {
                webAddress(site)?.let { url -> Quieter(UiText.ph(Placeholder.HEALTH_OPEN_SITE)) { openInCustomTab(context, url) } }
            }
        }
        if (r.hasPassword) {
            Quieter(UiText.ph(Placeholder.ITEM_COPY)) {
                c.revealSecret(r.itemId, SecretField.PASSWORD)?.let {
                    copyToClipboard(context, "password", it, maxOf(1, (model.clipboardClearMs() / 1000).toInt()))
                }
            }
        }
        ButtonRow(4) {
            for (result in CHECK_VERDICTS) {
                Quieter(UiText.ph(Placeholder.HEALTH_VERDICT, result), enabled = canWrite && !state.busy) { scope.launchOvertakable { said(c.recordCheck(r.itemId, result)) } }
            }
        }
        ButtonRow {
            Quieter(UiText.ph(Placeholder.HEALTH_SKIP)) { c.skipCheck() }
            Quieter(UiText.ph(Placeholder.HEALTH_STOP)) { c.stopCheckRun() }
        }
    }
}

/** The person's four verdicts, as the content takes them: it worked, it refused the password, gone, couldn't finish. */
internal val CHECK_VERDICTS: List<String> = listOf("ok", "bad", "gone", "blocked")

/**
 * The address a saved site opens at in the check run: an http or https address as it is, a bare host with https in
 * front, and nothing for any other scheme (a saved "site" is the person's data and never runs as anything else).
 */
/** A Health row's name and user name, each as one safe line (ItemText.label; Health's names come raw). */
internal fun nameLine(name: String, username: String): String =
    ItemText.label(name) + (if (username.isEmpty()) "" else "  ·  " + ItemText.label(username))

internal fun webAddress(site: String): String? {
    // The shared code's one rule for every address a screen opens (ItemText.openableAddress): http or https
    // as written, a bare host with https, never another scheme, a space, a control or format character, or a user name
    // before the host (`https://bank.example@evil.example` opens evil.example; the screen says
    // why, [carriesUserInfo]). On top of it this keeps its own belt: a backslash anywhere, which browsers read as a
    // slash, is not taken.
    if (site.contains('\\')) return null
    return ItemText.openableAddress(site)
}

/**
 * Whether [site] carries a user name or password before its host: an `@` in the part before the first `/`, `?` or `#`
 * after the scheme (or from the start, for a bare host). A backslash ends that part too, as browsers read it.
 */
internal fun carriesUserInfo(site: String): Boolean {
    val s = site.trim()
    val afterScheme = Regex("^[A-Za-z][A-Za-z0-9+.-]*://").find(s)?.let { s.substring(it.range.last + 1) } ?: s
    val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' && it != '\\' }
    return authority.contains('@')
}

/** Open [url] in a Custom Tab, arming the excursion so leaving for it does not lock; a refused launch drops the arm. */
private fun openInCustomTab(context: Context, url: String) {
    ExternalExcursion.begin()
    runCatching { CustomTabsIntent.Builder().build().launchUrl(context, Uri.parse(url)) }.onFailure { ExternalExcursion.clear() }
}

@Composable
private fun DuplicateCluster(c: VaultContent, d: DuplicateClusterView, canWrite: Boolean, said: (ActionResult) -> Unit) {
    val scope = rememberCoroutineScope()
    // The confirmation on show: null, "merge", or the id of the item to keep.
    var asking by remember(c, d.signature) { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Say(Placeholder.HEALTH_DUPLICATES, d.sites, style = MaterialTheme.typography.labelMedium)
        d.members.forEach { mbr ->
            Text(ItemText.label(mbr.name) + "  ·  " + ItemText.label(mbr.username) + "  ·  " + ItemText.label(mbr.vaultName), style = MaterialTheme.typography.bodyMedium)
            mbr.keepRefusal?.let { Say(UiText.Plain(it), style = MaterialTheme.typography.bodySmall) }
            if (mbr.keepRefusal == null) {
                if (asking == mbr.itemId) {
                    mbr.keepConfirm?.let { Say(UiText.Plain(it)) }
                    ButtonRow {
                        Quieter(UiText.ph(Placeholder.ITEM_BACK)) { asking = null }
                        Quieter(UiText.ph(Placeholder.HEALTH_KEEP_THIS), enabled = canWrite) { asking = null; scope.launchOvertakable { said(c.keepDuplicate(d.signature, mbr.itemId)) } }
                    }
                } else {
                    Quieter(UiText.ph(Placeholder.HEALTH_KEEP_THIS), enabled = canWrite) { asking = mbr.itemId }
                }
            }
        }
        d.mergeRefusal?.let { Say(UiText.Plain(it), style = MaterialTheme.typography.bodySmall) }
        if (asking == MERGE) {
            d.mergeConfirm?.let { Say(UiText.Plain(it)) }
            ButtonRow {
                Quieter(UiText.ph(Placeholder.ITEM_BACK)) { asking = null }
                Quieter(UiText.ph(Placeholder.HEALTH_MERGE), enabled = canWrite) { asking = null; scope.launchOvertakable { said(c.mergeDuplicates(d.signature)) } }
            }
        } else {
            ButtonRow {
                if (d.mergeRefusal == null) Quieter(UiText.ph(Placeholder.HEALTH_MERGE), enabled = canWrite) { asking = MERGE }
                Quieter(UiText.ph(Placeholder.HEALTH_NOT_DUPLICATES), enabled = canWrite) { scope.launchOvertakable { said(c.markNotDuplicates(d.signature)) } }
            }
        }
    }
}

private const val MERGE = "merge:"
