package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins for the Android vault-health surface (design 2026-08-23) that no pure core test can see.
 *
 * Two of these guard behaviours whose regression would be SILENT and serious: the breach map
 * never reaching disk, and the lock button's removal staying paired with lock-on-background.
 * The rest are source pins in the house `SurfaceCopyPinsTest` idiom — the wiring, not the logic,
 * because the logic is already graded against web by `spec/test-vectors/vaulthealth.json`.
 */
class HealthSurfaceTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    /**
     * Source with comments stripped. Every rule in this file is documented IN the source it
     * pins — "the breach map must never reach SharedPreferences", "— is not 'never used'" — so a
     * naive `contains` matches the prose explaining the rule and reports a violation that is
     * actually the rule being written down. Both of those fired on the first run of this file.
     */
    private fun code(name: String): String = src(name)
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    private val vm = src("AndvariViewModel.kt")
    private val health = src("HealthScreen.kt")
    private val main = src("MainActivity.kt")
    private val vmCode = code("AndvariViewModel.kt")
    private val healthCode = code("HealthScreen.kt")
    private val mainCode = code("MainActivity.kt")

    // ---- the wipe contract (CR-08 / WC-13 §E.4) ----

    /**
     * The breach map is derived from decrypted passwords — a >10M count fingerprints a top-100
     * password. Web's `localStorage` version was ripped out by audit for outliving sign-out; the
     * Android equivalents are `SharedPreferences` and the SQLite cache. Neither may appear
     * anywhere near it.
     */
    @Test
    fun breachMapIsNeverPersisted() {
        assertFalse(
            healthCode.contains("SharedPreferences") || vmCode.contains("SharedPreferences"),
            "the health surface must never touch SharedPreferences — the breach map is in-memory only",
        )
        assertFalse(healthCode.contains("SqlBox") || healthCode.contains("edit()"), "nor the on-disk cache")
        // It lives in UiState, which sessionCleared wipes; nothing writes it anywhere else.
        assertTrue(vm.contains("val breachByItem: Map<String, Long>? = null,"))
    }

    /** Both derived-from-secrets collections must ride the wipe choke point. */
    @Test
    fun sessionClearedDropsTheBreachMapAndTheUsageLedger() {
        val cleared = vm.substringAfter("internal fun UiState.sessionCleared").substringBefore("\n)")
        assertTrue(cleared.contains("breachByItem = null"), "breachByItem must clear on lock/sign-out")
        assertTrue(cleared.contains("usage = emptyMap()"), "the usage ledger must clear on lock/sign-out")
    }

    // ---- §7: the lock button and its prerequisite ----

    /**
     * The load-bearing pin of this release. Removing the lock button is only safe BECAUSE
     * lock-on-background exists: before it, `MainActivity` overrode only `onCreate`, nothing
     * locked on `onStop`, and the vault sat unlocked for up to the 900 s inactivity ceiling after
     * the user put the phone down. If someone deletes the observer, this fails and says why.
     */
    @Test
    fun theLockButtonIsGoneAndLockOnBackgroundReplacedIt() {
        assertFalse(main.contains("""IconButton(onClick = { vm.lock() })"""), "the manual lock button was removed by owner decision")
        assertTrue(main.contains("Lifecycle.Event.ON_STOP -> vm.lockFromBackground()"), "…which is ONLY safe because backgrounding locks")
        assertTrue(main.contains("ProcessLifecycleOwner.get()"), "process-level, so rotation is not mistaken for leaving")
        assertTrue(vm.contains("fun lockFromBackground()"))
    }

    /** The refresh icon became pull-to-refresh — same underlying op, not a second notion of sync. */
    @Test
    fun refreshIsAPullNotAnIcon() {
        assertFalse(main.contains("""Icon(Icons.Default.Refresh, "sync")"""), "the sync icon was replaced by pull-to-refresh")
        assertTrue(main.contains("PullToRefreshBox(isRefreshing = ui.busy, onRefresh = { vm.refresh() })"))
    }

    /**
     * H32 (audit 2026-09-13, G24 residue): the "Refresh" custom action must sit on nodes TalkBack
     * actually lands on in linear navigation — every vault row and the toolbar — not only on the
     * LazyColumn container it steps over. Both wiring legs: the row declares it, the list passes it.
     */
    @Test
    fun theRefreshActionReachesScreenReaderUsersOnEveryRow() {
        val row = mainCode.substringAfter("private fun VaultRow(").substringBefore("@Composable")
        assertTrue(row.contains("""CustomAccessibilityAction("Refresh") { onRefresh(); true }"""), "VaultRow must expose Refresh as a custom action")
        // A prefix match, not the whole call: H18 (audit 2026-09-13) added `pendingSync = …` after
        // `onRefresh`, and a pin on the closing paren would have failed on that unrelated argument
        // while still saying nothing about the property it guards (the list passes the refresh).
        assertTrue(mainCode.contains("VaultRow(item, vaultTags[item.vaultId], onRefresh = { vm.refresh() }"), "the vault list must pass the refresh to every row")
        assertTrue(
            mainCode.contains("""Column(Modifier.semantics { customActions = listOf(CustomAccessibilityAction("Refresh") { vm.refresh(); true }) }) {"""),
            "…and the toolbar, the first node linear navigation reaches",
        )
    }

    /** Health is reachable at all — a screen nobody can open is the failure this release exists
     *  to end, and it would otherwise pass every other test in this file. */
    @Test
    fun healthIsReachableFromTheVaultToolbar() {
        assertTrue(main.contains("""IconButton(onClick = { vm.openHealth() })"""))
        assertTrue(main.contains("is Screen.Health -> HealthScreen(vm, ui)"))
    }

    // ---- §5: the run leaves the app, and §7 must not seal it ----

    /**
     * H91 (audit 2026-09-13): this pin used to be a COUNT — five `ExternalExcursion.begin()`
     * occurrences in the RAW source. Two ways that lies. It counted prose: a comment mentioning
     * the call kept the total at five while a real arm was deleted, which is exactly the G01
     * ship-blocker (a save-as launched with no exemption, so the vault sealed mid-dialog) walking
     * back in under a green test. And it tied no arm to a launch: any five occurrences passed.
     *
     * So: comment-stripped source, and each arm asserted TOGETHER WITH the launch it protects.
     * The count stays as a completeness backstop — a sixth arm is either a new deliberate
     * excursion, which belongs in this list, or a background lock being skipped by accident.
     */
    @Test
    fun everyDeliberateExcursionIsExemptFromTheBackgroundLock() {
        assertTrue(health.contains("ExternalExcursion.begin()"), "the Custom Tab run must be exempt")
        val arms = listOf(
            "ExternalExcursion.begin(); importPicker.launch(" to "the CSV import file picker",
            "ExternalExcursion.begin(); picker.launch(" to "the attachment picker",
            "ExternalExcursion.begin(); saver.launch(" to "the attachment save-as dialog",
            "ExternalExcursion.begin(); csvSaver.launch(" to "the CSV export save-as dialog",
        )
        for ((expr, what) in arms) {
            assertTrue(mainCode.contains(expr), "$what must arm the exemption immediately before its launch — missing `$expr`")
        }
        // The backup save-as arms on its own line (the only multi-line arm), so it is matched as
        // begin() followed by ITS launch with nothing but whitespace between the two.
        assertTrue(
            Regex("""ExternalExcursion\.begin\(\)\s*\n\s*backupSaver\.launch\(""").containsMatchIn(mainCode),
            "the backup save-as dialog must arm the exemption immediately before backupSaver.launch",
        )
        assertEquals(
            arms.size + 1,
            Regex("ExternalExcursion\\.begin\\(\\)").findAll(mainCode).count(),
            "an ExternalExcursion arm exists that no launch above is tied to — every skipped lock must be a named, deliberate excursion",
        )
    }

    /**
     * H54 (audit 2026-09-13): lock-on-background's observer is composition-scoped, and
     * ProcessLifecycleOwner's ON_STOP is dispatched 700 ms after the last activity pauses — so on
     * API 29/30 a FINISHING activity (Back out of the vault list; a Recents swipe) disposes the
     * observer before the event it needs. The finishing path therefore locks for itself. Nothing
     * else in the process would: `onCleared` only clears the in-flight-op latch, and the 1 s idle
     * ticker dies with `viewModelScope`.
     */
    @Test
    fun aFinishingActivityLocksWithoutWaitingForTheDeferredOnStop() {
        assertTrue(
            mainCode.contains("if (isFinishing && !crashScreenShown) vm.lockOnExit()"),
            "MainActivity.onDestroy must lock when it is finishing (and never wake the ViewModel on the crash-screen path)",
        )
        val lockOnExit = vmCode.substringAfter("fun lockOnExit()").substringBefore("fun openHealth()")
        assertTrue(lockOnExit.contains("lock(reason = REASON_BACKGROUND)"), "…by locking the session")
        // UNCONDITIONAL by design: the exemptions all describe flows that leave this activity
        // ALIVE (a picker, a Custom Tab, an overlay), and the in-flight deferral has nothing left
        // to protect or to re-fire it once viewModelScope is cancelled. An exemption consulted
        // here would reopen the whole hole.
        assertFalse(lockOnExit.contains("ExternalExcursion"), "a finishing activity may not be excused by an excursion arm")
        assertFalse(lockOnExit.contains("InProcessOverlays"), "nor by the overlay exemption")
        assertFalse(lockOnExit.contains("deferredBackgroundLock"), "nor deferred behind an op that is about to be cancelled")
    }

    /** The arm is a ONE-SHOT. A launch that never happens must not leave the app unlockable.
     *  H57: it is also self-expiring — [ExternalExcursionTtlTest] pins the window's behaviour;
     *  this keeps pinning the seams that wire the one-shot into the lifecycle. */
    @Test
    fun theExcursionArmIsConsumedAndCleared() {
        val ex = src("ExternalExcursion.kt")
        assertTrue(ex.contains("fun consume(): Boolean"))
        assertTrue(ex.contains("armedAtMs = null"), "consume/clear must drop the arm")
        assertTrue(vm.contains("if (ExternalExcursion.consume()) return"))
        assertTrue(main.contains("Lifecycle.Event.ON_START -> { ExternalExcursion.clear(); vm.onProcessStart() }"))
        // R17: the ACTIVITY-resumed clear, the complement the TTL alone cannot replace. The
        // process ON_START above only fires after a process ON_STOP, and H57's OEM case — the
        // autofill picker drawn as a dialog over a still-STARTED activity — fires neither, so an
        // unconsumed arm rode the full five-minute window and could exempt the user's NEXT
        // genuine backgrounding. Pinned on the RESUMED block because that is the one hook that
        // fires on the dialog path.
        val resumed = mainCode.substringAfter("repeatOnLifecycle(Lifecycle.State.RESUMED)").substringBefore("setContent")
        assertTrue(
            resumed.contains("ExternalExcursion.clear()"),
            "an unused arm must be dropped when the ACTIVITY resumes, not only when the PROCESS restarts",
        )
        assertTrue(
            resumed.indexOf("ExternalExcursion.clear()") < resumed.indexOf("while (true)"),
            "…on entry to the resumed block, before the sync loop, so it runs exactly once per return",
        )
    }

    // ---- audit 2026-09-13: the lock-on-background legs that never landed ----

    private val lockFromBackground: String
        get() = vmCode.substringAfter("fun lockFromBackground()").substringBefore("fun onProcessStart()")

    /**
     * H08: the G12 in-flight deferral is a DEFERRAL. The busy branch RECORDS the request instead
     * of returning silently; the `_ui` collector (the single in-flight-op choke point) fires it
     * when the op ends in the background; ON_START voids it. DeferredBackgroundLockTest pins the
     * state machine — this pins that all three legs are wired to it.
     */
    @Test
    fun theDeferredBackgroundLockIsRecordedFiredAndVoided() {
        assertTrue(lockFromBackground.contains("deferredBackgroundLock.left()"), "ON_STOP must mark the app as backgrounded first")
        assertTrue(lockFromBackground.contains("{ deferredBackgroundLock.defer(); return }"), "the busy branch must record, not skip")
        assertTrue(vmCode.contains("if (deferredBackgroundLock.takeIfDue(inProgress)) lock(reason = REASON_BACKGROUND)"), "the op choke point must fire it")
        // R12: an ON_START caused by an autofill overlay is not the user returning — H09's rule, on the start leg.
        assertTrue(vmCode.contains("fun onProcessStart() = deferredBackgroundLock.returned(startedByOverlay = InProcessOverlays.lastStartWasOverlay())"), "ON_START must void it — unless an overlay woke the process")
        assertTrue(
            vmCode.indexOf("private val deferredBackgroundLock") < vmCode.indexOf("init {"),
            "declared before init — the collector runs on Main.immediate during construction",
        )
    }

    /**
     * H09: the design's third exemption — an autofill overlay closing is not leaving the app.
     * InProcessOverlaysTest pins the state machine and the manifest list; this pins the two
     * seams: the Application installs the tracker before any Activity, and the background lock
     * consults it before the excursion arm.
     */
    @Test
    fun anOverlayStopIsExemptFromTheBackgroundLock() {
        assertTrue(code("AndvariApplication.kt").contains("InProcessOverlays.install(this)"))
        assertTrue(lockFromBackground.contains("if (InProcessOverlays.lastStopWasOverlay()) return"))
        assertTrue(
            lockFromBackground.indexOf("InProcessOverlays.lastStopWasOverlay()") < lockFromBackground.indexOf("ExternalExcursion.consume()"),
            "an overlay stop must not burn a Custom-Tab/picker arm",
        )
    }

    /** H12: the pre-session recovery secret is bounded — by idle time (the ticker) and by
     *  leaving the app (lock-on-background's early `VaultSession == null` return must not skip it). */
    @Test
    fun theRecoverySecretIsZeroedOnIdleAndOnBackground() {
        val idle = vmCode.substringAfter("fun checkIdleLock()").substringBefore("fun backgroundSync()")
        assertTrue(idle.contains("recoverSecretIdleExpired(s.screen is Screen.Recover, s.recoverVerified, VaultSession.idleSeconds())"))
        assertTrue(idle.indexOf("recoverTimedOut()") < idle.indexOf("VaultSession.get() == null"), "checked BEFORE the session-null return")
        assertTrue(lockFromBackground.contains("if (_ui.value.screen is Screen.Recover && _ui.value.recoverVerified) recoverTimedOut()"))
        assertTrue(lockFromBackground.indexOf("recoverTimedOut()") < lockFromBackground.indexOf("VaultSession.get() == null"))
        val timedOut = vmCode.substringAfter("fun recoverTimedOut()").substringBefore("fun recoverVerify(")
        assertTrue(timedOut.contains("zeroPendingRecover()"), "the timeout must zero the secret")
        assertTrue(timedOut.contains("notice = RECOVER_TIMEOUT_NOTICE"), "…and say so with web's notice")
    }

    // ---- §5/§6: the promises the screens make ----

    /**
     * andvari never tries a password for you. The only honest test of a password is a person
     * using it, and a client that quietly probed sites with stored credentials would be doing
     * something nobody asked for. The run opens a site and gets out of the way.
     */
    @Test
    fun theVerificationRunNeverProbesASiteItself() {
        val run = health.substringAfter("private fun VerifyRunDialog").substringBefore("private fun openSite")
        for (banned in listOf("HttpClient", "URLConnection", "OkHttp", "fetch(")) {
            assertFalse(run.contains(banned), "the run must never make a request of its own ($banned)")
        }
        assertTrue(health.contains("Open the site and sign in yourself"))
    }

    /** No recorded use renders "—", never "never used" — different statements, one of them true.
     *  An Android autofill FILL is still unobservable, so this is what keeps the gap honest. */
    @Test
    fun absentUsageRendersADashNotNeverUsed() {
        assertTrue(health.contains("""("last used: " + (r.lastUsedAt?.let { relativeDaysLabel(it) } ?: "—")""".trimStart('(')))
        assertFalse(healthCode.contains("never used"), "absence is not a claim that the login was never used")
        assertFalse(mainCode.contains("never used"))
    }

    /** An unscanned vault shows "—" rather than a green zero: no finding is not "no breaches". */
    @Test
    fun anUnscannedVaultDoesNotClaimToBeClean() {
        assertTrue(health.contains("""breached?.toString() ?: "—""""))
        assertTrue(health.contains("ui.breachByItem == null || count == null -> \"breaches: —\""))
    }

    // ---- audit 2026-09-13: the run's controls web has and the phone lacked ----

    private val runDialog: String
        get() = healthCode.substringAfter("private fun VerifyRunDialog").substringBefore("private fun openSite")

    /** H27 (web Staleness.tsx:137,236-244 twin): "gone" records AND offers the delete, naming
     *  the item; never automatic. */
    @Test
    fun anAccountGoneVerdictOffersTheDeleteByName() {
        val record = vmCode.substringAfter("fun recordCheck(").substringBefore("fun removeGoneItem(")
        assertTrue(record.contains("""healthOfferDelete = if (result == "gone") itemId else null"""), "the offer is set once the save lands, and withdrawn by any other verdict")
        assertTrue(health.contains("“\$name” is marked as gone. Remove it from the vault?"), "web's sentence, naming the item")
        assertTrue(health.contains("""Text("Move to Deleted items")""") && health.contains("""Text("Keep it")"""), "web's two answers")
        assertTrue(vm.contains("\"Moved to Deleted items — it stays restorable there for 30 days.\""), "web's outcome sentence")
        assertFalse(healthCode.contains("vm.deleteItem("), "the offer must go through removeGoneItem, which clears the offer and states the outcome")
    }

    /**
     * H117 (design 2026-08-22 §4: "Wrong password → bad → offers: open the item / generate a new
     * password"). The design ratified FOUR verdicts on the stated grounds that each maps to a
     * different next action; "bad" mapped to none on any client, so a member who declared a
     * password broken was advanced to the next login with no path back to it. The offer is now
     * built, in [GoneOfferRow]'s shape and with web's words — and it must stay an OFFER: neither
     * button may rotate a credential by itself.
     */
    @Test
    fun aWrongPasswordVerdictOffersTheTwoRepairsByName() {
        val record = vmCode.substringAfter("fun recordCheck(").substringBefore("fun removeGoneItem(")
        assertTrue(
            record.contains("""healthOfferBad = if (result == "bad") itemId else null"""),
            "the offer is set once the save lands, and withdrawn by any other verdict",
        )
        assertTrue(
            record.contains("""healthOfferDelete = if (result == "gone") itemId else null"""),
            "…alongside the gone-offer: one verdict, one standing offer",
        )
        // R14: BYTE-IDENTICAL to web's Staleness.tsx `badSentence`. The two lanes each wrote this
        // sentence from the feature description and shipped two spellings behind three identical
        // button labels; web is the declared source of truth for this row.
        assertTrue(health.contains("“\$name” is marked as having the wrong password. Change it?"), "the sentence NAMES the login, in web's exact words")
        assertTrue(health.contains("""Text("Open the item")"""), "design §4's first offer")
        assertTrue(health.contains("""Text("Generate a new password")"""), "design §4's second offer")
        assertTrue(health.contains("""Text("Not now")"""), "…and a way to decline, like the gone-offer's Keep it")
        // Both offers are rendered in BOTH places the gone-offer is: the screen AND inside the
        // modal run dialog, which hides the screen underneath it.
        assertEquals(2, Regex("ui\\.healthOfferBad\\?\\.let \\{ BadOfferRow").findAll(healthCode).count())
        // The repair NAVIGATES; it never writes. A generate-and-save here would strand the member
        // on a password no login page has ever accepted.
        val repair = vmCode.substringAfter("fun repairBadItem(").substringBefore("fun keepBadOffer()")
        assertTrue(repair.contains("stopVerifyRun()"), "the run ends — the user is leaving to fix the item")
        assertTrue(repair.contains("pendingDetailId = itemId"), "…landing on the item that was just declared broken")
        // R15: the editor must open WITH the generated password already in the field (web's
        // `generateOnOpen`), or "Generate a new password" generates nothing on the phone and one
        // label carries two behaviours across the twins.
        assertTrue(repair.contains("if (edit) openEditor(itemId, generate = true)"), "the editor opens pre-generated, as on web")
        assertFalse(repair.contains("saveItem(") || repair.contains("PasswordGenerator"), "the offer must never change a password for the user")
        // …and the flag is a real editor-session flag, cleared like every other one: an ordinary
        // edit opened right after must not inherit a generate.
        assertTrue(vmCode.contains("fun openEditor(itemId: String?, newType: String = \"login\", generate: Boolean = false)"), "openEditor carries the flag")
        val open = vmCode.substringAfter("fun openEditor(").substringBefore("fun closeEditor()")
        assertTrue(open.contains("editorGenerateOnOpen = generate"), "…set per session")
        val close = vmCode.substringAfter("fun closeEditor()").substringBefore("fun editorTargetVanished()")
        assertTrue(close.contains("editorGenerateOnOpen = false"), "…and cleared with the session, like editorPendingUploads")
        // The editor actually acts on it, once, and says so in web's words.
        assertTrue(main.contains("if (vm.editorGenerateOnOpen && isLogin)"), "the editor fills a generated password at open")
        assertTrue(
            mainCode.contains("a new password is ready — change it on the site, then press Save to keep it here"),
            "…with web's notice: generated, revealed, and NOT saved yet",
        )
    }

    /** H28: the run card has Copy username / Copy password, on the shared clipboard window, and
     *  the password copy records a use (web's :262 rule). `healthClipboardSeconds()` finally
     *  has the caller it was written for. */
    @Test
    fun theRunCardCopiesOnTheSharedClipboardWindowAndRecordsTheUse() {
        assertTrue(runDialog.contains("vm.healthClipboardSeconds()"), "the helper built for these buttons must be the window they use")
        assertTrue(runDialog.contains("""copyToClipboard(ctx, "Username", row.username, clipClear)"""))
        assertTrue(
            Regex("vm\\.recordUse\\(row\\.itemId\\)\\s*copyToClipboard\\(ctx, \"Password\", password, clipClear\\)").containsMatchIn(runDialog),
            "the password copy IS a use, recorded before the copy",
        )
        assertEquals(1, Regex("fun healthClipboardSeconds\\(\\)").findAll(vm).count())
    }

    /** H29 (web Staleness.tsx:303-307/346 twin): three ways to start a run, web's labels. */
    @Test
    fun aSingleLoginCanBeCheckedWithoutRunningEverything() {
        assertTrue(vm.contains("fun startVerifyRun(queue: List<String> = stalenessRows().map { it.itemId })"))
        assertTrue(health.contains("Text(\"Check the \${unchecked.size} never-checked\")"))
        assertTrue(health.contains("""Text("Check everything, worst first")"""))
        assertTrue(health.contains("vm.startVerifyRun(listOf(r.itemId))"), "the per-row Check")
        assertFalse(health.contains("Start check run"), "the single over-everything starter is gone")
    }

    /** H30: the run announces where it is. The dialog's title changes in place on every advance
     *  (the case Compose announces) and carries the login's name; the refusal slot is ALWAYS
     *  composed so a refusal is a text change, not a populated mount. */
    @Test
    fun theRunAnnouncesEachAdvanceAndEachRefusal() {
        assertTrue(runDialog.contains("liveRegion = LiveRegionMode.Polite"))
        assertTrue(runDialog.contains("contentDescription = \"\${row.name} — check \$position\""))
        assertTrue(runDialog.contains("ui.healthMessage ?: \"\","), "the refusal Text must be present even when empty")
        assertFalse(runDialog.contains("ui.healthMessage?.let {"), "…never conditionally mounted")
    }

    /** H31 (AM-6's remedy; web Msg.tsx Announcer twin): the health notice has an ALWAYS-composed
     *  live region whose text mutates — the conditional NoticeBar stays as the sighted copy. */
    @Test
    fun theHealthNoticeHasAPersistentLiveRegion() {
        assertTrue(health.contains("HealthAnnouncer(ui.healthMessage)"))
        val announcer = healthCode.substringAfter("private fun HealthAnnouncer(").substringBefore("@Composable")
        assertTrue(announcer.contains("liveRegion = LiveRegionMode.Polite"))
        assertTrue(announcer.contains("message ?: \"\","), "composed with empty text when there is no message — present in the tree from the first frame")
        // R11: ONE region per message. NoticeBar is itself a polite live region, so the health
        // call site renders it silent — the web Msg.tsx / Announcer split (the visible strip has
        // no live role; the persistent announcer speaks).
        assertTrue(healthCode.contains("NoticeBar(it, vm::dismissHealthMessage, announce = false)"), "the health notice bar must not announce beside the announcer")
        assertTrue(mainCode.contains("internal fun NoticeBar(msg: String?, onDismiss: () -> Unit, announce: Boolean = true)"), "NoticeBar must carry the opt-out")
        val bar = mainCode.substringAfter("internal fun NoticeBar(").substringBefore("// ---- auth ----")
        assertTrue(bar.contains("if (announce) Modifier.semantics { liveRegion = LiveRegionMode.Polite } else Modifier"), "announce=false must drop the region, not just mute it")
    }

    /** H26: what the screen renders is the rev-checked map, never the raw scan result. */
    @Test
    fun theScreenRendersOnlyFreshBreachVerdicts() {
        assertTrue(health.contains("vm.freshBreachByItem()"))
        // R09: the pending-write ids ride into the gate (a queued edit keeps the prior rev).
        assertTrue(vmCode.contains("freshBreachVerdicts(u.breachByItem, u.breachScanRev, u.pendingSyncIds) { live[it] }"), "the gate must see the unflushed-write set")
        // R08: a retired verdict is fed into the tile's non-verdict channel with the failed ranges.
        assertTrue(healthCode.contains("val breachStale = breachVerdictsRetired(ui.breachByItem, breachByItem)"))
        assertTrue(healthCode.contains("HealthTiles(summary, dupes, staleSummary, breachByItem, ui.breachScanIncomplete || breachStale, rows)"), "the Breached tile must go neutral when a verdict was retired")
        assertTrue(vm.contains("val breachScanRev: Map<String, Long> = emptyMap(),"))
        val cleared = vm.substringAfter("internal fun UiState.sessionCleared").substringBefore("\n)")
        assertTrue(cleared.contains("breachScanRev = emptyMap()"), "the rev map rides the wipe with the count map")
        assertTrue(cleared.contains("healthOfferDelete = null"), "and so does the gone-offer")
        assertTrue(cleared.contains("healthOfferBad = null"), "…and the H117 wrong-password offer, which names an item")
        val tab = healthCode.substringAfter("private fun PasswordsTab(").substringBefore("private fun DuplicatesTab(")
        assertFalse(tab.contains("ui.breachByItem?.get("), "rows must read the fresh map, not the raw one")
    }

    /** Refusals are rendered VERBATIM — paraphrasing one on the way to the screen is how a
     *  refusal becomes a mystery. The screen prints what core returned. */
    @Test
    fun refusalsReachTheScreenUnparaphrased() {
        assertTrue(health.contains("ui.healthMessage?.let { NoticeBar(it, vm::dismissHealthMessage, announce = false) }"))
        assertTrue(vm.contains("_ui.value.copy(healthMessage = plan.refusal)"))
        assertTrue(vm.contains("_ui.value.copy(healthMessage = plan.keepRefusal)"))
        assertTrue(vm.contains("_ui.value.copy(healthMessage = plan.dismissRefusal)"))
    }

    // ---- the screen decides nothing ----

    /**
     * The whole point of Layer 1: rankings come from core, so the phone and the browser cannot
     * disagree. If this screen ever grows its own sort or its own threshold, that guarantee is
     * gone and no vector file will notice.
     */
    @Test
    fun theScreenRendersCoreDecisionsRatherThanItsOwn() {
        assertFalse(health.contains("sortedByDescending { it.updatedAt }"), "ranking belongs to core Staleness")
        assertFalse(health.contains("estimateStrength"), "scoring belongs to core Strength, via VaultHealth rows")
        for (call in listOf("vm.healthRows()", "vm.duplicateClusters()", "vm.stalenessRows()")) {
            assertTrue(health.contains(call), "$call must come from the ViewModel's core-backed accessor")
        }
    }

    /** The breach scan fetches each 5-hex prefix range ONCE — two passwords sharing a prefix must
     *  not cost two requests. Only the prefix ever leaves the device (spec 03 §8). */
    @Test
    fun theBreachScanBatchesByPrefix() {
        val scan = vm.substringAfter("fun scanBreaches()").substringBefore("// ---- the check ledger ----")
        assertTrue(scan.contains("groupBy({ Hibp.prefix"), "ranges must be grouped by prefix, not fetched per password")
        assertTrue(scan.contains("byPassword[r.password]?.let { r.itemId to it }"), "results key by itemId, never by the password")
    }
}
