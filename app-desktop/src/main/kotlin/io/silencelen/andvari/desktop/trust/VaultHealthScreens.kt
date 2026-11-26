package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CheckRunView
import io.silencelen.andvari.core.app.DuplicateClusterView
import io.silencelen.andvari.core.app.HealthView
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.desktop.CLIPBOARD_COPY_FAILED
import io.silencelen.andvari.desktop.copyWithAutoClear
import io.silencelen.andvari.desktop.openInBrowser

/**
 * Vault health, ported from the Android app: the tiles, the passwords with their strength, reuse and breaches, the
 * breach check, the duplicate clusters with merge, keep one and "not duplicates" (each behind the content's own
 * confirmation where it gives one) and the groups marked "not duplicates" with Put back; staleness with the check run,
 * its four verdicts, skip and stop, snoozing shown on request and Unsnooze; and the two offers a verdict raises (a gone
 * login to the trash, a refused password to open or to give a new one). Every verdict is the person's: nothing here
 * signs in or changes a password. [onOpenItem] opens an item from the bad-password offer: its detail, or its editor
 * with a new password unsaved.
 */
@Composable
internal fun HealthPanel(model: TrustModel, c: VaultContent, state: ContentState, h: HealthView, onOpenItem: (itemId: String, generate: Boolean) -> Unit) {
    val scope = rememberWorkScope()
    var answer by remember(c) { mutableStateOf<String?>(null) }
    fun said(r: ActionResult) {
        answer = sentence(r)
    }
    val canWrite = canSave(state) && !state.busy
    PageHeader(UiText.ph(Placeholder.HEALTH)) { c.closeHealth() }
    h.message?.let {
        Say(UiText.Plain(it))
        Quieter(UiText.ph(Placeholder.CLOSE)) { c.dismissHealthMessage() }
    }
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    h.offerDelete?.let { o ->
        Say(Placeholder.HEALTH_OFFER_GONE, o.name)
        Actions {
            Quieter(UiText.ph(Placeholder.HEALTH_KEEP_IT)) { c.keepGoneLogin() }
            Quieter(UiText.ph(Placeholder.HEALTH_TO_TRASH), enabled = canWrite) { scope.launch { said(c.trashGoneLogin()) } }
        }
    }
    h.offerBad?.let { o ->
        Say(Placeholder.HEALTH_OFFER_BAD, o.name)
        Actions {
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
    Say(
        Placeholder.HEALTH_TILES,
        t.logins.toString(), t.weak.toString(), t.reused.toString(), t.breached?.toString() ?: "?", t.duplicates.toString(),
        t.unchecked.toString(), t.failing.toString(),
    )
    t.breachedHint?.let { Say(UiText.Plain(it), style = MaterialTheme.typography.bodySmall) }
    h.scan?.let { Say(Placeholder.HEALTH_CHECKING, it.done.toString(), it.total.toString()) }
    Actions {
        Quieter(UiText.ph(Placeholder.HEALTH_CHECK_BREACHES), enabled = !state.busy && h.scan == null) { scope.launch { said(c.checkBreaches()) } }
        Quieter(UiText.ph(Placeholder.HEALTH_REFRESH), enabled = !state.busy) { c.refreshHealth() }
    }
    h.duplicates.forEach { DuplicateCluster(c, it, canWrite) { r -> said(r) } }
    if (h.notDuplicates.isNotEmpty()) {
        Say(Placeholder.HEALTH_MARKED_NOT_DUPLICATES, style = MaterialTheme.typography.labelMedium)
        h.notDuplicates.forEach { d ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(d.sites + "  ·  " + d.members.joinToString(", ") { it.name }, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                Quieter(UiText.ph(Placeholder.HEALTH_PUT_BACK), enabled = canWrite) { scope.launch { said(c.restoreDuplicates(d.signature)) } }
            }
        }
    }
    StalenessList(c, state, h, canWrite) { r -> said(r) }
    h.passwords.forEach { p ->
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text(p.name, style = MaterialTheme.typography.bodyLarge)
            val marks = listOfNotNull(
                p.strength,
                // [reused] counts the OTHER logins with this exact password.
                reusedLine(p.reused).shown().takeIf { p.reused > 0 },
                p.breaches?.takeIf { it > 0 }?.let { UiText.ph(Placeholder.HEALTH_BREACHED, it.toString()).shown() },
            )
            Text(marks.joinToString("  ·  "), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * Staleness: each login with where it stands and its dates, worst first; snoozed ones only on request (the counts at the
 * top never change with it), each with Unsnooze; the check run over all of them or the never-checked only, or one login.
 */
@Composable
private fun StalenessList(c: VaultContent, state: ContentState, h: HealthView, canWrite: Boolean, said: (ActionResult) -> Unit) {
    val scope = rememberWorkScope()
    Say(Placeholder.HEALTH_STALENESS, style = MaterialTheme.typography.labelMedium)
    Tick(UiText.ph(Placeholder.HEALTH_SHOW_SNOOZED), h.showSnoozed) { c.setHealthShowSnoozed(it) }
    if (h.allSnoozed) Say(Placeholder.HEALTH_ALL_SNOOZED)
    if (h.run == null && h.staleness.isNotEmpty()) {
        Actions {
            Quieter(UiText.ph(Placeholder.HEALTH_RUN_ALL), enabled = canWrite) { c.startCheckRun(false) }
            if (h.staleness.any { it.neverChecked }) {
                Quieter(UiText.ph(Placeholder.HEALTH_RUN_NEVER_CHECKED), enabled = canWrite) { c.startCheckRun(true) }
            }
        }
    }
    h.staleness.forEach { s ->
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text(s.name + (if (s.username.isEmpty()) "" else "  ·  " + s.username), style = MaterialTheme.typography.bodyLarge)
            Text(s.state, style = MaterialTheme.typography.bodySmall, color = if (s.failing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            if (s.dates.isNotEmpty()) Text(s.dates, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Actions {
                if (h.run == null) Quieter(UiText.ph(Placeholder.HEALTH_CHECK_THIS), enabled = canWrite) { c.checkLogin(s.itemId) }
                if (s.snoozed) Quieter(UiText.ph(Placeholder.HEALTH_UNSNOOZE), enabled = canWrite && !state.busy) { scope.launch { said(c.unsnoozeLogin(s.itemId)) } }
            }
        }
    }
}

/**
 * The check run on one login: its place in the run, the site to sign in at (opened in the system's browser; the
 * desktop does not lock on leaving the window, so nothing is armed), its password to copy (cleared after the policy's
 * window), and what happened, in the person's own verdict. Skip writes nothing; Stop ends the run.
 */
@Composable
private fun CheckRunPanel(model: TrustModel, c: VaultContent, state: ContentState, r: CheckRunView, canWrite: Boolean, said: (ActionResult) -> Unit) {
    val scope = rememberWorkScope()
    var copyFailed by remember(c, r.itemId) { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Say(Placeholder.HEALTH_RUN_POSITION, r.position.toString(), r.total.toString(), style = MaterialTheme.typography.labelMedium)
        Text(r.name + (if (r.username.isEmpty()) "" else "  ·  " + r.username), style = MaterialTheme.typography.bodyLarge)
        r.site?.let { site ->
            Text(site, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
            // Note N9: an address with a user name or password before the host is not opened, and the screen says why.
            if (carriesUserInfo(site)) {
                Say(Placeholder.OPEN_SITE_USERINFO)
            } else {
                webAddress(site)?.let { url -> Quieter(UiText.ph(Placeholder.HEALTH_OPEN_SITE)) { openInBrowser(url) } }
            }
        }
        if (r.hasPassword) {
            Quieter(UiText.ph(Placeholder.ITEM_COPY)) {
                c.revealSecret(r.itemId, SecretField.PASSWORD)?.let { copyFailed = !copyWithAutoClear(it, clipboardSeconds(model)) }
            }
            if (copyFailed) Say(UiText.Plain(CLIPBOARD_COPY_FAILED), color = MaterialTheme.colorScheme.error)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            for (result in CHECK_VERDICTS) {
                Quieter(UiText.ph(Placeholder.HEALTH_VERDICT, result), enabled = canWrite && !state.busy) { scope.launch { said(c.recordCheck(r.itemId, result)) } }
            }
        }
        Actions {
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
internal fun webAddress(site: String): String? {
    val s = site.trim()
    if (s.isEmpty() || s.any { it.isWhitespace() || Character.isISOControl(it) }) return null
    // `https://bank.example@evil.example/` opens evil.example. Never opened.
    if (carriesUserInfo(s)) return null
    val lower = s.lowercase()
    if (lower.startsWith("https://") || lower.startsWith("http://")) return s
    if (Regex("^[a-z][a-z0-9+.-]*:").containsMatchIn(lower)) return null
    return "https://$s"
}

/**
 * Whether [site] carries a user name or password before its host (note N9): an `@` in the part between the scheme's
 * `//` (or the start, for a bare host) and the first `/`, `?`, `#` or `\` (browsers read a backslash as a slash).
 */
internal fun carriesUserInfo(site: String): Boolean {
    val s = site.trim()
    val start = s.indexOf("//").let { if (it >= 0 && Regex("^[A-Za-z][A-Za-z0-9+.-]*:").containsMatchIn(s.substring(0, it))) it + 2 else 0 }
    val rest = s.substring(start)
    val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' || it == '\\' }.let { if (it < 0) rest.length else it }
    return '@' in rest.substring(0, end)
}

@Composable
private fun DuplicateCluster(c: VaultContent, d: DuplicateClusterView, canWrite: Boolean, said: (ActionResult) -> Unit) {
    val scope = rememberWorkScope()
    // The confirmation on show: null, [MERGE], or the id of the item to keep.
    var asking by remember(c, d.signature) { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Say(Placeholder.HEALTH_DUPLICATES, d.sites, style = MaterialTheme.typography.labelMedium)
        d.members.forEach { mbr ->
            Text(mbr.name + "  ·  " + mbr.username + "  ·  " + mbr.vaultName, style = MaterialTheme.typography.bodyMedium)
            mbr.keepRefusal?.let { Say(UiText.Plain(it), style = MaterialTheme.typography.bodySmall) }
            if (mbr.keepRefusal == null) {
                if (asking == mbr.itemId) {
                    mbr.keepConfirm?.let { Say(UiText.Plain(it)) }
                    Actions {
                        Quieter(UiText.ph(Placeholder.BACK)) { asking = null }
                        Quieter(UiText.ph(Placeholder.HEALTH_KEEP_THIS), enabled = canWrite) { asking = null; scope.launch { said(c.keepDuplicate(d.signature, mbr.itemId)) } }
                    }
                } else {
                    Quieter(UiText.ph(Placeholder.HEALTH_KEEP_THIS), enabled = canWrite) { asking = mbr.itemId }
                }
            }
        }
        d.mergeRefusal?.let { Say(UiText.Plain(it), style = MaterialTheme.typography.bodySmall) }
        if (asking == MERGE) {
            d.mergeConfirm?.let { Say(UiText.Plain(it)) }
            Actions {
                Quieter(UiText.ph(Placeholder.BACK)) { asking = null }
                Quieter(UiText.ph(Placeholder.HEALTH_MERGE), enabled = canWrite) { asking = null; scope.launch { said(c.mergeDuplicates(d.signature)) } }
            }
        } else {
            Actions {
                if (d.mergeRefusal == null) Quieter(UiText.ph(Placeholder.HEALTH_MERGE), enabled = canWrite) { asking = MERGE }
                Quieter(UiText.ph(Placeholder.HEALTH_NOT_DUPLICATES), enabled = canWrite) { scope.launch { said(c.markNotDuplicates(d.signature)) } }
            }
        }
    }
}

private const val MERGE = "merge:"
