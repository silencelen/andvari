package io.silencelen.andvari.app

import android.content.Context
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.client.Duplicates
import io.silencelen.andvari.core.client.Staleness
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.VaultHealth

/**
 * Vault health on the phone (design `docs/design/2026-08-23-android-vault-health.md`).
 *
 * **This file renders and calls; it decides nothing.** Every ranking, cluster, survivor choice
 * and refusal comes from core [VaultHealth] / [Duplicates] / [Staleness] — the same pure modules
 * the web client uses, graded against it by `spec/test-vectors/vaulthealth.json`. If a number
 * here disagrees with the browser, the bug is in core or in this file's plumbing, never in a
 * second opinion computed locally.
 *
 * Web's `<table>` becomes cards in a [LazyColumn]: a five-column table is unreadable at phone
 * width, and the vault list already pays for eager composition once (Cut K) — a health list over
 * a large vault must not re-learn that.
 */
@OptIn(ExperimentalLayoutApi::class, androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun HealthScreen(vm: AndvariViewModel, ui: UiState) {
    BackHandler(onBack = vm::closeHealth)
    val rows = vm.healthRows()
    val dupes = vm.duplicateClusters()
    val stale = vm.stalenessRows()
    val staleSummary = Staleness.stalenessSummary(stale)
    val summary = VaultHealth.summarize(rows)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vault health", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = { IconButton(onClick = vm::closeHealth) { Icon(Icons.Default.ArrowBack, "back") } },
                actions = {
                    TextButton(onClick = vm::scanBreaches, enabled = !ui.breachScanning && rows.isNotEmpty()) {
                        Text(
                            when {
                                ui.breachScanning -> "Scanning… ${ui.breachProgress.first}/${ui.breachProgress.second}"
                                ui.breachByItem != null -> "Rescan"
                                else -> "Scan"
                            },
                        )
                    }
                },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            ErrorBar(ui.error, vm::clearError)
            NoticeBar(ui.notice, vm::clearNotice)
            // Refusals from the plan* functions render VERBATIM — they are the reason, and
            // paraphrasing one on the way to the screen is how a refusal becomes a mystery.
            ui.healthMessage?.let { NoticeBar(it, vm::dismissHealthMessage) }

            HealthTiles(summary, dupes, staleSummary, ui.breachByItem, rows)

            TabRow(selectedTabIndex = TABS.indexOfFirst { it.first == ui.healthTab }.coerceAtLeast(0)) {
                for ((key, label) in TABS) {
                    Tab(ui.healthTab == key, { vm.setHealthTab(key) }, text = { Text(label) })
                }
            }

            when (ui.healthTab) {
                "duplicates" -> DuplicatesTab(vm, ui, dupes)
                "staleness" -> StalenessTab(vm, ui, stale)
                else -> PasswordsTab(vm, ui, rows)
            }
        }
    }

    if (ui.verifyRunning) VerifyRunDialog(vm, ui)
}

private val TABS = listOf("passwords" to "Passwords", "duplicates" to "Duplicates", "staleness" to "Staleness")

/**
 * The always-visible summary. Seven tiles do not fit a phone row, so they wrap — and they are
 * derived from the SAME collections the tabs below render, so a tile can never disagree with the
 * list under it.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun HealthTiles(
    summary: VaultHealth.HealthSummary,
    dupes: List<Duplicates.DuplicateCluster>,
    stale: Staleness.StalenessSummary,
    breachByItem: Map<String, Long>?,
    rows: List<VaultHealth.HealthRow>,
) {
    // null = never scanned. "—" is NOT zero: an unscanned vault has no breach finding, which is
    // a different statement from "no breaches", and only one of them would be true.
    val breached = breachByItem?.let { m -> rows.count { (m[it.itemId] ?: 0L) > 0L } }
    val activeDupes = dupes.count { !it.dismissed }
    FlowRow(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Tile("Logins", summary.logins.toString(), null)
        Tile("Weak", summary.weak.toString(), summary.weak > 0)
        Tile("Reused", summary.reused.toString(), summary.reused > 0)
        Tile("Breached", breached?.toString() ?: "—", breached?.let { it > 0 })
        Tile("Duplicates", activeDupes.toString(), activeDupes > 0)
        Tile("Unchecked", stale.unchecked.toString(), stale.unchecked > 0)
        Tile("Failing", stale.failing.toString(), stale.failing > 0)
    }
}

/** [bad] null = no verdict (the unscanned "—"), so the tile stays neutral rather than green. */
@Composable
private fun Tile(label: String, value: String, bad: Boolean?) {
    val tone = when (bad) {
        null -> MaterialTheme.colorScheme.onSurfaceVariant
        true -> MaterialTheme.colorScheme.error
        false -> MaterialTheme.colorScheme.primary
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
            // One announcement per tile: "Weak, 3" rather than two orphaned strings.
            Text(value, style = MaterialTheme.typography.titleMedium, color = tone, modifier = Modifier.clearAndSetSemantics {})
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.semantics { contentDescription = "$label: $value" },
            )
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------------------------

@Composable
private fun PasswordsTab(vm: AndvariViewModel, ui: UiState, rows: List<VaultHealth.HealthRow>) {
    if (rows.isEmpty()) {
        Empty("No logins with passwords yet — nothing to assess.")
        return
    }
    // Highest breach count first, then alphabetical; unscanned/no-breach items tie at 0.
    val sorted = remember(rows, ui.breachByItem) {
        rows.sortedWith(
            compareByDescending<VaultHealth.HealthRow> { ui.breachByItem?.get(it.itemId) ?: 0L }
                .thenBy { it.name },
        )
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp)) {
        items(sorted, key = { it.itemId }) { r ->
            val count = ui.breachByItem?.get(r.itemId)
            Card(
                onClick = { vm.openItemFromHealth(r.itemId) },
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text(r.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "strength: ${Strength.label(r.strength)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (r.strength <= 1) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (r.reused > 0) {
                            Text(
                                "reused in ${r.reused} other${if (r.reused > 1) "s" else ""}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        if (r.hasTotp) {
                            Text("2FA", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                        }
                    }
                    Text(
                        when {
                            // Absent from the map after a scan means the RANGE failed, not that
                            // the password is clean — "—" either way, never a false "none".
                            ui.breachByItem == null || count == null -> "breaches: —"
                            count > 0L -> "breaches: $count"
                            else -> "breaches: none"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if ((count ?: 0L) > 0L) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Duplicates
// ---------------------------------------------------------------------------------------------

@Composable
private fun DuplicatesTab(vm: AndvariViewModel, ui: UiState, clusters: List<Duplicates.DuplicateCluster>) {
    val active = clusters.filter { !it.dismissed }
    val dismissed = clusters.filter { it.dismissed }
    if (clusters.isEmpty()) {
        Empty("No duplicate entries — every account is saved exactly once.")
        return
    }
    var confirmMerge by remember { mutableStateOf<Duplicates.MergePlan?>(null) }
    var confirmKeep by remember { mutableStateOf<Pair<Duplicates.DuplicateCluster, String>?>(null) }

    LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp)) {
        item(key = "intro") {
            Text(
                "Copies sitting in different vaults are listed but never merged — removing one " +
                    "would take it off every household member's devices.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }
        items(active, key = { it.signature }) { c ->
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text(c.sites.joinToString(", "), style = MaterialTheme.typography.titleSmall)
                    Text(
                        if (c.kind == Duplicates.Kind.EXACT) "Same password on every copy."
                        else "Same account, different passwords — one of these is out of date.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(6.dp))
                    for (m in c.members) {
                        Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(m.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(
                                    m.username.ifEmpty { "(no username)" },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            // audit F03: every member row names its VAULT. A merge moves real
                            // items out of a real place, and this screen used to name neither.
                            Text(
                                vm.vaultInfos().firstOrNull { it.vaultId == m.vaultId }?.name ?: "shared",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.tertiary,
                            )
                            if (c.kind == Duplicates.Kind.DIFFERS) {
                                Spacer(Modifier.width(8.dp))
                                TextButton(onClick = {
                                    val refusal = vm.keepRefusalFor(c.members.map { it.itemId }, m.itemId)
                                    if (refusal != null) vm.showHealthMessage(refusal) else confirmKeep = c to m.itemId
                                }) { Text("Keep this") }
                            }
                        }
                    }
                    c.mergeRefusal?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 6.dp))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        c.merge?.let { plan -> TextButton(onClick = { confirmMerge = plan }) { Text("Merge") } }
                        TextButton(onClick = { vm.dismissDuplicates(c.members.map { it.itemId }, c.signature) }) {
                            Text("Not duplicates")
                        }
                    }
                }
            }
        }
        if (dismissed.isNotEmpty()) {
            item(key = "dismissed-header") {
                Text("Marked not duplicates", style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 12.dp))
            }
            items(dismissed, key = { "d-" + it.signature }) { c ->
                Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(c.sites.joinToString(", "), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    // An empty signature CLEARS the acknowledgment rather than writing it blank.
                    TextButton(onClick = { vm.dismissDuplicates(c.members.map { it.itemId }, "") }) { Text("Restore") }
                }
            }
        }
    }

    confirmMerge?.let { plan ->
        val survivorName = vm.item(plan.survivorId)?.doc?.name ?: "this copy"
        AlertDialog(
            onDismissRequest = { confirmMerge = null },
            title = { Text("Merge ${plan.loserIds.size + 1} copies?") },
            text = {
                Text(
                    "Keep “$survivorName” and move the other ${plan.loserIds.size} to Deleted items " +
                        "(kept 30 days). Saved sites from every copy are carried over.",
                )
            },
            confirmButton = { TextButton(onClick = { vm.mergeDuplicates(plan); confirmMerge = null }) { Text("Merge") } },
            dismissButton = { TextButton(onClick = { confirmMerge = null }) { Text("Cancel") } },
        )
    }
    confirmKeep?.let { (c, keepId) ->
        val keepName = c.members.firstOrNull { it.itemId == keepId }?.name ?: "this copy"
        AlertDialog(
            onDismissRequest = { confirmKeep = null },
            title = { Text("Keep “$keepName”?") },
            text = {
                Text(
                    "The other ${c.members.size - 1} go to Deleted items (kept 30 days), and their " +
                        "passwords stay in the kept item's password history.",
                )
            },
            confirmButton = {
                TextButton(onClick = { vm.keepDuplicate(c.members.map { it.itemId }, keepId); confirmKeep = null }) { Text("Keep") }
            },
            dismissButton = { TextButton(onClick = { confirmKeep = null }) { Text("Cancel") } },
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Staleness
// ---------------------------------------------------------------------------------------------

@Composable
private fun StalenessTab(vm: AndvariViewModel, ui: UiState, rows: List<Staleness.StalenessRow>) {
    if (rows.isEmpty() && !ui.showSnoozed) {
        Empty("Nothing to check — every login has been confirmed recently.")
        return
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp)) {
        item(key = "controls") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = vm::startVerifyRun, enabled = rows.isNotEmpty()) { Text("Start check run") }
                Spacer(Modifier.weight(1f))
                TextButton(onClick = { vm.setShowSnoozed(!ui.showSnoozed) }) {
                    Text(if (ui.showSnoozed) "Hide snoozed" else "Show snoozed")
                }
            }
        }
        items(rows, key = { it.itemId }) { r ->
            Card(
                onClick = { vm.openItemFromHealth(r.itemId) },
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text(r.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        bucketLabel(r),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (r.bucket == Staleness.StaleBucket.FAILING) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        // "—" is NOT "never used" — see UiState.usage. Two different statements.
                        "last used: " + (r.lastUsedAt?.let { relativeDaysLabel(it) } ?: "—") +
                            " · last changed: " + relativeDaysLabel(r.updatedAt),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (r.snoozed) {
                        TextButton(onClick = { vm.unsnooze(r.itemId) }) { Text("Unsnooze") }
                    }
                }
            }
        }
    }
}

private fun bucketLabel(r: Staleness.StalenessRow): String = when (r.bucket) {
    // The verdict itself, not a paraphrase: an unrecognized result from a future client reads as
    // "checked" with no verdict styling, which is the open-vocabulary contract (spec 02 §3).
    Staleness.StaleBucket.FAILING -> "last check failed (${r.check?.result})"
    Staleness.StaleBucket.NEVER -> "never checked"
    Staleness.StaleBucket.OVER_YEAR -> "not checked in over a year"
    Staleness.StaleBucket.SIX_TO_TWELVE -> "not checked in 6-12 months"
    Staleness.StaleBucket.RECENT ->
        if (r.check?.result == "ok") "checked recently" else "checked recently (verdict unknown)"
}

// ---------------------------------------------------------------------------------------------
// The guided verification run
// ---------------------------------------------------------------------------------------------

/**
 * The run (design §5). The phone is the one client where the tester and the thing being tested
 * live in the same place: the saved site opens in a Custom Tab, andvari's own autofill fills it,
 * and Back returns here to record what happened.
 *
 * **andvari never tries a password for you.** There is no request here that carries a credential
 * anywhere — the human signs in and says what they saw. A client that quietly probed sites with
 * stored credentials would be doing something nobody asked for.
 *
 * All six controls are equals. The browser pass on web found the nudge inverted — the four ways
 * to ANSWER rendered subordinate to the two ways to answer nothing — and nothing in a unit suite
 * can see visual weight, so it is stated here rather than re-earned.
 */
@Composable
private fun VerifyRunDialog(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContext.current
    val row = vm.verifyCurrent()
    if (row == null) {
        // The queue outlived its items (a sync removed one) — end rather than show an empty run.
        vm.stopVerifyRun()
        return
    }
    AlertDialog(
        onDismissRequest = vm::stopVerifyRun,
        title = { Text("Check ${ui.verifyIndex + 1} of ${ui.verifyQueue.size}") },
        text = {
            Column {
                Text(row.name, style = MaterialTheme.typography.titleSmall)
                Text(
                    row.username.ifEmpty { "(no username)" },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                Text("Open the site and sign in yourself, then say what happened.", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(
                        onClick = {
                            row.firstUri?.let {
                                // Opening the site counts as a use, exactly as it does on web.
                                vm.recordUse(row.itemId)
                                openSite(ctx, it)
                            }
                        },
                        enabled = row.firstUri != null,
                    ) { Text(if (row.firstUri != null) "Open site" else "no saved site to open") }
                }
                Spacer(Modifier.height(4.dp))
                // Four ways to answer…
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { vm.recordCheck(row.itemId, "ok") { vm.verifyAdvance() } }) { Text("It worked") }
                    TextButton(onClick = { vm.recordCheck(row.itemId, "bad") { vm.verifyAdvance() } }) { Text("Refused") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { vm.recordCheck(row.itemId, "gone") { vm.verifyAdvance() } }) { Text("Account gone") }
                    TextButton(onClick = {
                        vm.recordCheck(row.itemId, "blocked", Staleness.SNOOZE_MS) { vm.verifyAdvance() }
                    }) { Text("Couldn't finish") }
                }
            }
        },
        // …and two ways to answer nothing, carrying exactly the same weight. Skip writes NOTHING.
        confirmButton = { TextButton(onClick = vm::verifyAdvance) { Text("Skip") } },
        dismissButton = { TextButton(onClick = vm::stopVerifyRun) { Text("Stop") } },
    )
}

/**
 * Open a saved site in a Custom Tab. Only a WEB uri ever reaches here (core filters the row's
 * [Staleness.StalenessRow.firstUri] to navigable ones), and a device with no browser at all must
 * not crash the run.
 */
private fun openSite(ctx: Context, uri: String) {
    val url = if (uri.startsWith("http://") || uri.startsWith("https://")) uri else "https://$uri"
    // §5.1: the run leaves the app BY DESIGN, and §7 locks on leaving the app. Exempt this one
    // backgrounding, or "Open site" would seal the vault the run is standing in.
    ExternalExcursion.begin()
    runCatching { CustomTabsIntent.Builder().build().launchUrl(ctx, Uri.parse(url)) }
        // No browser at all (or the intent was refused): the arm would otherwise sit unused
        // until the next unrelated backgrounding. Drop it now.
        .onFailure { ExternalExcursion.clear() }
}

@Composable
private fun Empty(message: String) {
    Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(32.dp))
        Text(message, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
