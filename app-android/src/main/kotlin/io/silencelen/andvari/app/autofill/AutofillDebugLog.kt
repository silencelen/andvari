package io.silencelen.andvari.app.autofill

import android.content.Context
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import io.silencelen.andvari.core.client.autofill.UriMatch
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * Field-diagnostic log for the autofill fill path (the "why did nothing pop up" surface).
 * Two layers, both under filesDir so the Autofill-status screen (UI) can read what the
 * autofill service wrote even across process/instance boundaries:
 *
 *  - `autofill-last.json` — a single-event summary of the MOST RECENT fill request.
 *    ALWAYS written (it's one small file, no history), so the status screen has something
 *    to show even with debugging off.
 *  - `autofill-log.jsonl` — a ring buffer of the last [RING_MAX] events, appended ONLY
 *    while the "Debug autofill (24h)" toggle is armed ([SessionStore.autofillDebugUntil]
 *    holds an absolute expiry timestamp; past it the toggle silently self-disarms).
 *    The ring is DELETED — not just frozen — the moment the toggle is off/expired
 *    (checked on record and on read), so disarming also purges the collected history.
 *
 * NEVER-LOG RULE (absolute, mirrors AndvariAutofillService's): no field values, no
 * usernames/passwords, no item names, no full URIs. Allowed: timestamps, calling package,
 * trust verdict + reason enum (+ the observed signing-cert digest — a public value — on
 * mismatch, so the status screen doubles as the pin-capture tool), per-field
 * {kind, host-only frame domain, winning classifier signal}, per-field match COUNTS,
 * item COUNTS, terminal reason enums, and exception CLASS NAMES — NEVER exception
 * messages (they routinely echo their input: a SerializationException quotes the JSON,
 * an IllegalArgumentException quotes the offending URI, RemoteViews/Parcel errors quote
 * view content). When in doubt: enum or count, never a value.
 *
 * Every entry point is wrapped in runCatching — logging can never break a fill or crash
 * the service process. All file writes run on [writer], a single background thread:
 * onFillRequest runs on the time-boxed main thread and must never wait on disk for
 * diagnostics.
 */
object AutofillDebugLog {
    const val RING_MAX = 50
    const val DEBUG_WINDOW_MS = 24L * 60 * 60 * 1000 // the "(24h)" in the toggle label
    private const val LAST_FILE = "autofill-last.json"
    private const val LOG_FILE = "autofill-log.jsonl"

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /**
     * Single background thread for ALL file writes. Fire-and-forget: a fill's diagnostics
     * need not land before the FillCallback replies, and the one thread keeps event order
     * and makes the ring's read-modify-write race-free. Daemon — never blocks process
     * exit. Tradeoff (accepted): an event enqueued microseconds before process death can
     * be lost — fine for diagnostics, far better than main-thread I/O in a fill callback.
     */
    private val writer = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "andvari-autofill-log").apply { isDaemon = true }
    }

    /** Cached [SessionStore.autofillDebugUntil] so the per-fill armed check doesn't hit
     *  SharedPreferences after first load. The status screen writes the toggle through
     *  [setDebugUntil], which refreshes this (service + UI share one process). */
    @Volatile
    private var debugUntilCache: Long = Long.MIN_VALUE // MIN_VALUE = not loaded yet

    /** Where the fill terminated — one enum per formerly-silent exit. */
    enum class FillReason {
        NO_STRUCTURE, // request carried no AssistStructure / no activity component
        SELF_FILL, // the requester is andvari itself (self-guard)
        SIGNED_OUT, // no persisted session / empty token — no unlock row possible
        NO_FIELDS, // structure parsed but nothing fillable: no USERNAME/PASSWORD field and no PAN-anchored card form
        LOCKED_ROW_SHOWN, // vault locked → "Unlock andvari" authentication row offered
        NO_ITEMS, // unlocked, fields present, but zero usable login items in the vault
        NO_URI_MATCH, // unlocked, login items exist, none match this app/site (fallback row shown)
        DATASETS, // n credential datasets offered (detail = n)
        EXCEPTION, // fill path threw (detail = exception CLASS name only — never the message)
        UNKNOWN, // terminated without computed counts (build aborted mid-way) — no definite verdict
    }

    /** Why the calling package did / didn't get web-domain trust. */
    enum class TrustReason {
        TRUSTED, // pinned browser, signing cert matches
        CERT_MISMATCH, // pinned browser, installed cert differs (observedDigest captured)
        NO_PIN_DIGEST, // known browser, empty pin set — fail closed (observedDigest captured)
        NOT_IN_PINS, // presents web domains but isn't a known browser package
        NATIVE_APP, // no web domains in the form / not a browser — androidapp:// matching only
    }

    /** The EXCEPTION detail: class name ONLY. Messages are banned (see never-log rule). */
    fun exceptionDetail(t: Throwable): String = t::class.simpleName ?: "Exception"

    @Serializable
    data class FieldSummary(
        val kind: String, // USERNAME / PASSWORD / CC_* (a kind name, never a value)
        val host: String? = null, // frame domain, host-only (never a full URI)
        val signal: String = "", // winning classifier signal, e.g. "hint:password"
        // RAW candidate count for THIS field: logins that carry a credential of the
        // field's kind AND match its target — BEFORE the MAX_DATASETS cap (-1 = unknown;
        // card fields always stay -1 — their candidates are not counted per field).
        val matches: Int = -1,
    )

    @Serializable
    data class FillEvent(
        val ts: Long, // epoch ms
        val origin: String, // "service" | "unlock"
        val reason: String, // FillReason name
        val detail: String? = null, // DATASETS → n; EXCEPTION → class name (never a message)
        val pkg: String? = null, // calling package
        val trust: String? = null, // TrustReason name
        val observedDigest: String? = null, // caller's signing-cert digest on CERT_MISMATCH/NO_PIN_DIGEST
        val fields: List<FieldSummary> = emptyList(),
        val inline: Boolean = false, // an InlineSuggestionsRequest was present
    )

    // ---- recording ----

    /** Append [event] (asynchronously, on [writer]): last-event summary always; ring
     *  buffer only while debug is armed — and the ring file is PURGED when it isn't, so
     *  a disabled/expired toggle also deletes what was collected.
     *  Exception: SELF_FILL never overwrites the summary — andvari's OWN password fields
     *  fire fill requests (the self-guard rejects them), and letting those clobber the
     *  interesting browser event the user just reproduced would blank the status screen
     *  the moment they open the app to look at it. */
    fun record(context: Context, event: FillEvent) {
        runCatching {
            val app = context.applicationContext
            // EVERYTHING below runs on the writer thread — including the armed check, so
            // even the first-ever SharedPreferences load never lands on the fill thread.
            writer.execute {
                runCatching {
                    val line = json.encodeToString(FillEvent.serializer(), event)
                    if (event.reason != FillReason.SELF_FILL.name) File(app.filesDir, LAST_FILE).writeText(line)
                    val log = File(app.filesDir, LOG_FILE)
                    if (!debugEnabled(app)) {
                        log.delete() // disarmed/expired → purge, don't just stop appending
                        return@execute
                    }
                    val lines = (if (log.exists()) log.readLines().filter { it.isNotBlank() } else emptyList()) + line
                    log.writeText(lines.takeLast(RING_MAX).joinToString("\n", postfix = "\n"))
                }
            }
        }
    }

    /** True while the "Debug autofill (24h)" toggle is on and unexpired. */
    fun debugEnabled(context: Context): Boolean = runCatching {
        var until = debugUntilCache
        if (until == Long.MIN_VALUE) {
            until = SessionStore(context.applicationContext).autofillDebugUntil
            debugUntilCache = until
        }
        until > System.currentTimeMillis()
    }.getOrDefault(false)

    /** The status screen's toggle writer: persists the expiry, refreshes the cache, and
     *  purges the ring immediately when disarming (finding: expiry must delete, not freeze). */
    fun setDebugUntil(context: Context, until: Long) {
        runCatching {
            val app = context.applicationContext
            SessionStore(app).autofillDebugUntil = until
            debugUntilCache = until
            if (until <= System.currentTimeMillis()) writer.execute { runCatching { File(app.filesDir, LOG_FILE).delete() } }
        }
    }

    // ---- status-screen reads ----

    fun lastEvent(context: Context): FillEvent? = runCatching {
        val f = File(context.filesDir, LAST_FILE)
        if (!f.exists()) return null
        json.decodeFromString(FillEvent.serializer(), f.readText())
    }.getOrNull()

    /** The raw ring buffer (jsonl) — "" (and the file purged) unless debug is armed NOW. */
    fun ringText(context: Context): String = runCatching {
        val f = File(context.filesDir, LOG_FILE)
        if (!debugEnabled(context)) {
            if (f.exists()) writer.execute { runCatching { f.delete() } }
            return ""
        }
        f.takeIf { it.exists() }?.readText() ?: ""
    }.getOrDefault("")

    // ---- trust verdict (diagnostic only — NEVER gates a fill; TrustedBrowsers does) ----

    /**
     * Explains [TrustedBrowsers.isTrusted]'s verdict for the status screen. The observed
     * digest is captured only for the two cases where it's the actionable fix
     * (CERT_MISMATCH / NO_PIN_DIGEST → pin exactly this value in BrowserCertPins).
     */
    fun trustVerdict(context: Context, pkg: String, form: ParsedForm): Pair<TrustReason, String?> = runCatching {
        val pins = BrowserCertPins.TABLE[pkg]
        when {
            pins == null ->
                if ((form.fields + form.ccFields).any { it.webDomain != null }) TrustReason.NOT_IN_PINS to null
                else TrustReason.NATIVE_APP to null
            pins.isEmpty() -> TrustReason.NO_PIN_DIGEST to TrustedBrowsers.observedCertDigest(context, pkg)
            TrustedBrowsers.isTrusted(context, pkg) -> TrustReason.TRUSTED to null
            else -> TrustReason.CERT_MISMATCH to TrustedBrowsers.observedCertDigest(context, pkg)
        }
    }.getOrDefault(TrustReason.NATIVE_APP to null)

    /**
     * Mutable per-request collector threaded through the fill path. Every setter is
     * throw-proof; [finish] records exactly once (later calls are ignored) so an
     * exception handler can't double-log a request that already terminated cleanly.
     */
    class FillTrace(private val origin: String = "service") {
        var pkg: String? = null
        var inline: Boolean = false
        var formFieldCount: Int = -1 // classified fillable fields, login + card (-1 = form never parsed)
        var loginItemCount: Int = -1 // usable login items seen by DatasetBuilder (-1 = not counted)
        var datasetCount: Int = -1 // credential + card datasets built, fallback row excluded (-1 = not counted)
        var fallbackRowShown: Boolean = false // the "Open andvari" row made it into the response
        private var trust: TrustReason? = null
        private var observedDigest: String? = null
        private var fields: List<FieldSummary> = emptyList()
        private var done = false

        fun setForm(form: ParsedForm) {
            runCatching {
                // Login fields FIRST — setMatchCounts is index-parallel to form.fields, so the
                // card fields ride at the tail with kind/host/signal only (matches stays -1).
                val all = form.fields + form.ccFields
                formFieldCount = all.size
                fields = all.map {
                    FieldSummary(
                        kind = it.kind.name,
                        host = it.webDomain?.let { d -> UriMatch.normalizeHost(d) },
                        signal = it.signal,
                    )
                }
            }
        }

        fun setTrust(context: Context, form: ParsedForm) {
            runCatching {
                val (reason, digest) = trustVerdict(context, pkg ?: return, form)
                trust = reason
                observedDigest = digest
            }
        }

        /** Per-field raw candidate counts (pre-cap), parallel to the form's field list. */
        fun setMatchCounts(counts: List<Int>) {
            runCatching { fields = fields.mapIndexed { i, f -> f.copy(matches = counts.getOrElse(i) { -1 }) } }
        }

        fun finish(context: Context, reason: FillReason, detail: String? = null) {
            runCatching {
                if (done) return
                done = true
                record(
                    context,
                    FillEvent(
                        ts = System.currentTimeMillis(),
                        origin = origin,
                        reason = reason.name,
                        detail = detail,
                        pkg = pkg,
                        trust = trust?.name,
                        observedDigest = observedDigest,
                        fields = fields,
                        inline = inline,
                    ),
                )
            }
        }

        /**
         * Terminal reason for the unlocked build path, from what DatasetBuilder counted.
         * Definite verdicts require the counts to actually be KNOWN: if annotate() never
         * ran (counts still -1) or the no-match fallback row failed to build, this must
         * NOT claim a confident NO_URI_MATCH — that's UNKNOWN (the build aborted mid-way).
         */
        fun finishFromBuild(context: Context) {
            when {
                formFieldCount == 0 -> finish(context, FillReason.NO_FIELDS)
                datasetCount > 0 -> finish(context, FillReason.DATASETS, datasetCount.toString())
                datasetCount == 0 && loginItemCount == 0 -> finish(context, FillReason.NO_ITEMS)
                datasetCount == 0 && loginItemCount > 0 && fallbackRowShown -> finish(context, FillReason.NO_URI_MATCH)
                else -> finish(context, FillReason.UNKNOWN)
            }
        }
    }
}
