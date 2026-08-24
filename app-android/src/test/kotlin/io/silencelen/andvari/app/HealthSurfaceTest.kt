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

    /** Health is reachable at all — a screen nobody can open is the failure this release exists
     *  to end, and it would otherwise pass every other test in this file. */
    @Test
    fun healthIsReachableFromTheVaultToolbar() {
        assertTrue(main.contains("""IconButton(onClick = { vm.openHealth() })"""))
        assertTrue(main.contains("is Screen.Health -> HealthScreen(vm, ui)"))
    }

    // ---- §5: the run leaves the app, and §7 must not seal it ----

    @Test
    fun everyDeliberateExcursionIsExemptFromTheBackgroundLock() {
        assertTrue(health.contains("ExternalExcursion.begin()"), "the Custom Tab run must be exempt")
        assertEquals(
            2,
            Regex("ExternalExcursion\\.begin\\(\\)").findAll(main).count(),
            "both file pickers (CSV import, attachments) must be exempt",
        )
    }

    /** The arm is a ONE-SHOT. A launch that never happens must not leave the app unlockable. */
    @Test
    fun theExcursionArmIsConsumedAndCleared() {
        val ex = src("ExternalExcursion.kt")
        assertTrue(ex.contains("fun consume(): Boolean"))
        assertTrue(ex.contains("armed = false"))
        assertTrue(vm.contains("if (ExternalExcursion.consume()) return"))
        assertTrue(main.contains("Lifecycle.Event.ON_START -> ExternalExcursion.clear()"))
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

    /** Refusals are rendered VERBATIM — paraphrasing one on the way to the screen is how a
     *  refusal becomes a mystery. The screen prints what core returned. */
    @Test
    fun refusalsReachTheScreenUnparaphrased() {
        assertTrue(health.contains("ui.healthMessage?.let { NoticeBar(it, vm::dismissHealthMessage) }"))
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
