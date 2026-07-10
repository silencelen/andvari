package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Totp

/**
 * CSV import (spec 06) — 100% client-side, pure (no IO, no crypto beyond TOTP parsing).
 * The Kotlin REFERENCE implementation: tools/vector-gen emits import.json from this code,
 * spec/test-vectors/import-foreign.json pins the 0.8.0 additions, and the web TS twin
 * (web/src/import/csv.ts) must parse identically. Formats: Chrome/Edge (+ the Chromium
 * family), Firefox, Bitwarden, LastPass, 1Password (design 2026-07-09 + amendments).
 */
object CsvImport {
    const val MAX_BYTES = 10 * 1024 * 1024
    const val MAX_ROWS = 10_000

    /** Cross-port determinism (the CardNormalize.TRIMMABLE precedent): every adapter-level
     *  trim uses ONLY this pinned set, never platform trim()/isWhitespace/`\s` — those
     *  disagree at the Unicode margins (JS String.trim()/`\s` strips U+FEFF where the JVM
     *  keeps it; JVM isWhitespace strips U+001C..U+001F where JS keeps them), and the same
     *  bytes must parse identically on every client. U+FEFF joins the set here (unlike the
     *  card set) because a residual BOM from a re-saved/concatenated export lands INSIDE
     *  header and data cells and must trim identically everywhere (a `http://sn<FEFF>` url
     *  is a NOTE on every client, never a credential-less login whose body is dropped).
     *  Vector-pinned in import-foreign.json; web twin: csv.ts csvTrim. */
    private const val TRIMMABLE = " \t\n\r\u000B\u000C\uFEFF"
    private fun String.csvTrim(): String = trim { it in TRIMMABLE }

    /** [wire] is the cross-impl string (vectors, TS twin) — "1password" can't be a Kotlin name. */
    enum class ImportFormat(val wire: String) {
        CHROME("chrome"),
        FIREFOX("firefox"),
        BITWARDEN("bitwarden"),
        LASTPASS("lastpass"),
        ONE_PASSWORD("1password"),
    }

    /** Row kind (spec 06 §9.1) — vectors encode the lowercase name. */
    enum class RowKind { LOGIN, NOTE }

    class ImportException(val code: String) : Exception(code) // too_large | too_many_rows | unrecognized_header

    data class ParsedRow(
        val name: String,
        val url: String, // the row's primary url (= uris[0] or ""); dedupe + name fallback key on it
        val username: String,
        val password: String,
        val notes: String,
        val timePasswordChangedMs: Long?,
        val totp: String? = null,
        val kind: RowKind = RowKind.LOGIN,
        val favorite: Boolean = false,
        val uris: List<String> = emptyList(), // full uri list (Bitwarden A4 multi-uri split)
        val totpUnsupported: Boolean = false, // totp cell rejected → kept as text in notes (A5)
    )

    data class RowError(val line: Int, val code: String) // wrong_field_count | bad_quote

    data class Parsed(
        val format: ImportFormat,
        val rows: List<ParsedRow>,
        val errors: List<RowError>,
        /** False when the file has NO totp column → totp is a WILDCARD in vault rules 1–2 (A7). */
        val totpColumn: Boolean = true,
        val archivedSkipped: List<String> = emptyList(), // 1Password archived-truthy rows, by name
        val unknownTypeSkipped: List<String> = emptyList(), // Bitwarden non-login/note rows, by name
    )

    /** Light projections of the TARGET personal vault (F75) — decrypted client-side by the
     *  caller and built ONLY via [projections] (A8: one core-owned builder, never ad-hoc
     *  mapping at call sites). Absent fields map to "" ([] and [""] uris are equivalent). */
    data class LoginProjection(
        val name: String,
        val uris: List<String>,
        val username: String,
        val password: String,
        val totp: String? = null,
    )

    data class NoteProjection(val name: String, val notes: String)

    data class ImportProjections(
        val logins: List<LoginProjection> = emptyList(),
        val notes: List<NoteProjection> = emptyList(),
        /** ALL personal item display names (every type) — the A9 rename-until-free pool. */
        val names: List<String> = emptyList(),
    )

    data class ImportReport(
        val imported: Int,
        val skippedEmpty: Int,
        val collapsed: Int,
        val flagged: List<String>,
        val alreadyInVault: List<String> = emptyList(),
        val passwordDiffers: List<String> = emptyList(),
        val totpDiffers: List<String> = emptyList(),
        val archivedSkipped: List<String> = emptyList(),
        val unknownTypeSkipped: List<String> = emptyList(),
        val totpUnsupported: List<String> = emptyList(),
        val noteItems: List<String> = emptyList(),
        val errors: List<RowError> = emptyList(),
    )

    /** itemId minted ONCE at plan time so a retried import replays idempotently (spec 06 §4). */
    data class PlannedItem(val itemId: String, val doc: ItemDoc)

    data class ImportPlan(val items: List<PlannedItem>, val report: ImportReport)

    /**
     * UI helper (NOT part of the twin's vector surface; the web mirror is
     * `csv.ts rowOrdinalsByLine`): the 1-based DATA-ROW ordinal of each record's starting
     * physical line, derived with the SAME reader — so every client renders a [RowError]
     * as "row N (file line M)" (design amendment A9) without re-implementing quote-aware
     * line accounting. A multi-line quoted note otherwise makes "line 1237" unmatchable to
     * the row a spreadsheet shows. Blank lines are excluded exactly as [parse] excludes
     * them, and a record's start line is unique, so the map is total over error lines.
     */
    fun rowOrdinalsByLine(bytes: ByteArray): Map<Int, Int> {
        var text = bytes.decodeToString()
        if (text.isNotEmpty() && text[0] == '﻿') text = text.substring(1)
        val out = LinkedHashMap<Int, Int>()
        var ordinal = 0
        for (rec in Rfc4180.parse(text).drop(1)) {
            if (rec.fields.size == 1 && rec.fields[0].isEmpty()) continue
            out[rec.line] = ++ordinal
        }
        return out
    }

    // ---- parse ----

    fun parse(bytes: ByteArray): Parsed {
        if (bytes.size > MAX_BYTES) throw ImportException("too_large")
        var text = bytes.decodeToString() // lenient UTF-8 (invalid → U+FFFD)
        if (text.isNotEmpty() && text[0] == '﻿') text = text.substring(1) // strip BOM

        val records = Rfc4180.parse(text)
        if (records.isEmpty()) throw ImportException("unrecognized_header")
        val header = records[0].fields.map { it.csvTrim().lowercase() } // pinned trim: a 2nd-BOM header cell must detect identically cross-impl
        val format = detectFormat(header) ?: throw ImportException("unrecognized_header")

        val dataRecords = records.drop(1).filterNot { it.fields.size == 1 && it.fields[0].isEmpty() } // drop blank lines
        if (dataRecords.size > MAX_ROWS) throw ImportException("too_many_rows")

        return when (format) {
            ImportFormat.CHROME, ImportFormat.FIREFOX -> parseBrowser(format, header, dataRecords)
            ImportFormat.BITWARDEN -> parseBitwarden(header, dataRecords)
            ImportFormat.LASTPASS -> parseLastPass(header, dataRecords)
            ImportFormat.ONE_PASSWORD -> parseOnePassword(header, dataRecords)
        }
    }

    /** Detection = SPECIFICITY-ORDERED required-subset matching (design A3; order is
     *  load-bearing: LastPass's header is a superset of Chrome's required set). */
    private fun detectFormat(header: List<String>): ImportFormat? {
        val h = header.toSet()
        if (BITWARDEN_REQUIRED.all { it in h }) return ImportFormat.BITWARDEN
        if (LASTPASS_REQUIRED.all { it in h }) return ImportFormat.LASTPASS
        if (ONE_PASSWORD_REQUIRED.all { it in h }) return ImportFormat.ONE_PASSWORD
        if (listOf("url", "username", "password").all { it in h } &&
            (setOf("guid", "httprealm", "formactionorigin").any { it in h })
        ) return ImportFormat.FIREFOX
        if (listOf("name", "url", "username", "password").all { it in h }) return ImportFormat.CHROME
        return null
    }

    private val BITWARDEN_REQUIRED = setOf("type", "name", "login_uri", "login_username", "login_password")
    private val LASTPASS_REQUIRED = setOf("url", "username", "password", "extra", "name", "grouping") // totp/fav optional (pre-2023 files)
    private val ONE_PASSWORD_REQUIRED = setOf("title", "url", "username", "password", "otpauth") // favorite/archived/tags/notes optional

    /** Per-record guard shared by every format loop: bad quoting and field-count mismatches
     *  keep the existing RowError taxonomy; good rows reach [body]. */
    private inline fun eachRow(
        dataRecords: List<Rfc4180.RawRecord>,
        headerSize: Int,
        errors: MutableList<RowError>,
        body: (List<String>) -> Unit,
    ) {
        for (rec in dataRecords) {
            if (rec.badQuote) { errors.add(RowError(rec.line, "bad_quote")); continue }
            if (rec.fields.size != headerSize) { errors.add(RowError(rec.line, "wrong_field_count")); continue }
            body(rec.fields)
        }
    }

    /** Chrome/Edge + Firefox — the original (vector-frozen) mapping, unchanged. */
    private fun parseBrowser(format: ImportFormat, header: List<String>, dataRecords: List<Rfc4180.RawRecord>): Parsed {
        fun col(name: String) = header.indexOf(name)
        val iName = col("name"); val iUrl = col("url"); val iUser = col("username"); val iPass = col("password")
        val iNote = if (col("note") >= 0) col("note") else col("notes")
        val iRealm = col("httprealm"); val iPwChanged = col("timepasswordchanged")
        val iTotp = col("totp") // andvari CSV round-trip column (spec 06 §1 / 07 §1); browsers lack it

        val rows = ArrayList<ParsedRow>()
        val errors = ArrayList<RowError>()
        eachRow(dataRecords, header.size, errors) { f ->
            val url = f.getOrElse(iUrl) { "" }
            val username = f.getOrElse(iUser) { "" }
            val password = f.getOrElse(iPass) { "" }
            var notes = if (iNote >= 0) f.getOrElse(iNote) { "" } else ""
            if (format == ImportFormat.FIREFOX && iRealm >= 0) {
                val realm = f.getOrElse(iRealm) { "" }
                if (realm.isNotEmpty()) notes = if (notes.isEmpty()) "HTTP realm: $realm" else "$notes\nHTTP realm: $realm"
            }
            val rawName = if (format == ImportFormat.CHROME && iName >= 0) f.getOrElse(iName) { "" } else ""
            val name = if (rawName.isNotEmpty()) rawName else nameFallback(url)
            val pwChanged = if (iPwChanged >= 0) f.getOrElse(iPwChanged) { "" }.csvTrim().toLongOrNull() else null
            val totp = if (iTotp >= 0) f.getOrElse(iTotp) { "" }.csvTrim().ifEmpty { null } else null
            rows.add(
                ParsedRow(
                    name, url, username, password, notes, pwChanged, totp,
                    uris = if (url.isNotEmpty()) listOf(url) else emptyList(),
                ),
            )
        }
        return Parsed(format, rows, errors, totpColumn = iTotp >= 0)
    }

    /** Bitwarden personal/org CSV (spec 06 §6): type=login|note rows; `fields` append (A2),
     *  multi-uri split (A4), truthy favorite (A6), totp via the shared normalize (A5). */
    private fun parseBitwarden(header: List<String>, dataRecords: List<Rfc4180.RawRecord>): Parsed {
        fun col(name: String) = header.indexOf(name)
        val iType = col("type"); val iName = col("name"); val iNotes = col("notes"); val iFields = col("fields")
        val iFav = col("favorite"); val iUri = col("login_uri"); val iUser = col("login_username")
        val iPass = col("login_password"); val iTotp = col("login_totp") // folder/reprompt/collections ignored

        val rows = ArrayList<ParsedRow>()
        val errors = ArrayList<RowError>()
        val unknownTypeSkipped = ArrayList<String>()
        eachRow(dataRecords, header.size, errors) { f ->
            val name = f.getOrElse(iName) { "" }
            val favorite = truthy(if (iFav >= 0) f.getOrElse(iFav) { "" } else "")
            val notesCell = if (iNotes >= 0) f.getOrElse(iNotes) { "" } else ""
            val fieldsCell = if (iFields >= 0) f.getOrElse(iFields) { "" } else ""
            when (f.getOrElse(iType) { "" }.csvTrim().lowercase()) {
                "note" -> rows.add(
                    ParsedRow(
                        name = name, url = "", username = "", password = "",
                        notes = assembleNotes(notesCell, fieldsCell, null), timePasswordChangedMs = null,
                        kind = RowKind.NOTE, favorite = favorite,
                    ),
                )
                "login" -> {
                    val uris = splitUris(f.getOrElse(iUri) { "" })
                    val url = uris.firstOrNull() ?: ""
                    val t = adaptTotp(if (iTotp >= 0) f.getOrElse(iTotp) { "" } else "")
                    rows.add(
                        ParsedRow(
                            name = name.ifEmpty { nameFallback(url) }, url = url,
                            username = f.getOrElse(iUser) { "" }, password = f.getOrElse(iPass) { "" },
                            notes = assembleNotes(notesCell, fieldsCell, t.noteLine), timePasswordChangedMs = null,
                            totp = t.totp, favorite = favorite, uris = uris, totpUnsupported = t.unsupported,
                        ),
                    )
                }
                else -> unknownTypeSkipped.add(name) // cards/identities/…: skipped + enumerated
            }
        }
        return Parsed(
            ImportFormat.BITWARDEN, rows, errors,
            totpColumn = iTotp >= 0, unknownTypeSkipped = unknownTypeSkipped,
        )
    }

    /** LastPass CSV (spec 06 §7): url=="http://sn" rows are secure notes (extra = the body,
     *  templated blobs imported verbatim); grouping ignored; pre-2023 files lack totp. */
    private fun parseLastPass(header: List<String>, dataRecords: List<Rfc4180.RawRecord>): Parsed {
        fun col(name: String) = header.indexOf(name)
        val iUrl = col("url"); val iUser = col("username"); val iPass = col("password")
        val iExtra = col("extra"); val iName = col("name"); val iFav = col("fav"); val iTotp = col("totp")

        val rows = ArrayList<ParsedRow>()
        val errors = ArrayList<RowError>()
        eachRow(dataRecords, header.size, errors) { f ->
            val url = f.getOrElse(iUrl) { "" }
            val name = f.getOrElse(iName) { "" }
            val extra = f.getOrElse(iExtra) { "" }
            val favorite = truthy(if (iFav >= 0) f.getOrElse(iFav) { "" } else "")
            if (url.csvTrim() == "http://sn") { // pinned trim: `http://sn<FEFF>` is a NOTE on every client
                rows.add(
                    ParsedRow(
                        name = name, url = "", username = "", password = "", notes = extra,
                        timePasswordChangedMs = null, kind = RowKind.NOTE, favorite = favorite,
                    ),
                )
            } else {
                val t = adaptTotp(if (iTotp >= 0) f.getOrElse(iTotp) { "" } else "")
                rows.add(
                    ParsedRow(
                        name = name.ifEmpty { nameFallback(url) }, url = url,
                        username = f.getOrElse(iUser) { "" }, password = f.getOrElse(iPass) { "" },
                        notes = assembleNotes(extra, "", t.noteLine), timePasswordChangedMs = null,
                        totp = t.totp, favorite = favorite,
                        uris = if (url.isNotEmpty()) listOf(url) else emptyList(), totpUnsupported = t.unsupported,
                    ),
                )
            }
        }
        return Parsed(ImportFormat.LASTPASS, rows, errors, totpColumn = iTotp >= 0)
    }

    /** 1Password-8 CSV (spec 06 §8) — also matches Apple/Safari exports (pinned free win).
     *  archived-truthy rows are skipped + enumerated (deliberately shelved by the user). */
    private fun parseOnePassword(header: List<String>, dataRecords: List<Rfc4180.RawRecord>): Parsed {
        fun col(name: String) = header.indexOf(name)
        val iTitle = col("title"); val iUrl = col("url"); val iUser = col("username"); val iPass = col("password")
        val iOtp = col("otpauth"); val iFav = col("favorite"); val iArch = col("archived"); val iNotes = col("notes") // tags ignored

        val rows = ArrayList<ParsedRow>()
        val errors = ArrayList<RowError>()
        val archivedSkipped = ArrayList<String>()
        eachRow(dataRecords, header.size, errors) { f ->
            val url = f.getOrElse(iUrl) { "" }
            val name = f.getOrElse(iTitle) { "" }.ifEmpty { nameFallback(url) }
            if (truthy(if (iArch >= 0) f.getOrElse(iArch) { "" } else "")) {
                archivedSkipped.add(name)
            } else {
                val t = adaptTotp(if (iOtp >= 0) f.getOrElse(iOtp) { "" } else "")
                rows.add(
                    ParsedRow(
                        name = name, url = url,
                        username = f.getOrElse(iUser) { "" }, password = f.getOrElse(iPass) { "" },
                        notes = assembleNotes(if (iNotes >= 0) f.getOrElse(iNotes) { "" } else "", "", t.noteLine),
                        timePasswordChangedMs = null, totp = t.totp,
                        favorite = truthy(if (iFav >= 0) f.getOrElse(iFav) { "" } else ""),
                        uris = if (url.isNotEmpty()) listOf(url) else emptyList(), totpUnsupported = t.unsupported,
                    ),
                )
            }
        }
        return Parsed(ImportFormat.ONE_PASSWORD, rows, errors, totpColumn = iOtp >= 0, archivedSkipped = archivedSkipped)
    }

    // ---- adapter helpers (spec 06 §9) ----

    /** A6 — the ONE truthiness predicate for favorite/archived flags across all formats
     *  (pinned csvTrim: `1<U+001C>` and `1<FEFF>` are falsy on EVERY client, identically). */
    private fun truthy(cell: String): Boolean = cell.csvTrim().lowercase() in TRUTHY

    private val TRUTHY = setOf("1", "true", "y", "yes")

    private class AdaptedTotp(val totp: String?, val noteLine: String?, val unsupported: Boolean)

    /** A5 reject-don't-corrupt: normalize via the ONE shared [Totp.normalize]; a value the
     *  otpauth parser refuses (steam://, hotp, junk) is NEVER stored in login.totp — it is
     *  preserved as a notes line and enumerated (report bucket `totpUnsupported`). */
    private fun adaptTotp(cell: String): AdaptedTotp {
        val raw = cell.csvTrim()
        if (raw.isEmpty()) return AdaptedTotp(null, null, false)
        val normalized = Totp.normalize(raw)
        return if (parsesAsOtpauth(normalized)) AdaptedTotp(normalized, null, false)
        else AdaptedTotp(null, "Unsupported TOTP (kept as text): $raw", true)
    }

    private fun parsesAsOtpauth(value: String): Boolean =
        try { Totp.parseUri(value); true } catch (e: CryptoException) { false }

    /** Notes assembly (pinned order): base notes, then the Bitwarden custom-fields block
     *  (A2 — note rows too), then the unsupported-TOTP line; parts joined by "\n". */
    private fun assembleNotes(base: String, fields: String, totpLine: String?): String {
        val parts = ArrayList<String>(3)
        if (base.isNotEmpty()) parts.add(base)
        if (fields.isNotEmpty()) parts.add("— custom fields —\n$fields")
        if (totpLine != null) parts.add(totpLine)
        return parts.joinToString("\n")
    }

    /** A4 — Bitwarden comma-joins multi-uri logins; verbatim storage would kill UriMatch.
     *  Segments are trimmed, empties dropped (a literal comma inside one uri is accepted loss). */
    private fun splitUris(cell: String): List<String> =
        cell.split(',').map { it.csvTrim() }.filter { it.isNotEmpty() }

    // ---- plan (skip / dedupe / rename), vault-aware (F75) ----

    /** Pre-F75 signature — plans against an EMPTY vault (import.json-frozen behavior).
     *  Kept for vector-gen and tests; UI callers pass real projections (A8: refuse, don't
     *  degrade, when the vault is locked/unsynced). */
    fun plan(parsed: Parsed, newId: () -> String): ImportPlan = plan(parsed, ImportProjections(), newId)

    /** A8 — the ONE core-owned projection builder. Callers pass the decrypted docs of the
     *  PERSONAL vault only (imports land there; shared-vault copies are different items). */
    fun projections(docs: List<ItemDoc>): ImportProjections {
        val logins = ArrayList<LoginProjection>()
        val notes = ArrayList<NoteProjection>()
        val names = ArrayList<String>(docs.size)
        for (d in docs) {
            names.add(d.name)
            when (d.type) {
                "login" -> logins.add(
                    LoginProjection(
                        name = d.name, uris = d.login?.uris ?: emptyList(),
                        username = d.login?.username ?: "", password = d.login?.password ?: "",
                        totp = d.login?.totp,
                    ),
                )
                "note" -> notes.add(NoteProjection(d.name, d.notes ?: ""))
            }
        }
        return ImportProjections(logins, notes, names)
    }

    /**
     * Vault-aware plan (spec 06 §4 addendum). Per row, kind-scoped (A1):
     * skip-empty → vault rule 1 (exact match → alreadyInVault) → vault rule 2 (logins only:
     * same site+user, different secret → import renamed, passwordDiffers/totpDiffers) →
     * in-file exact collapse → in-file group rename, groupCount SEEDED from the vault's
     * (url, username) counts, "(k)" bumped until free (A9). The existing vault is NEVER
     * mutated — zero-destruction. Keying per A7: url equality is the spec 02 §3.1
     * normalizer's equivalence against EVERY saved uri; totp compares by PARSED parameters
     * (wildcard when the file has no totp column); NUL-joined composite keys throughout.
     */
    fun plan(parsed: Parsed, existing: ImportProjections, newId: () -> String): ImportPlan {
        // -- vault-side index (built once; the guard excludes url-less+username-less items
        //    from site/user maps — they match through the (name, password[, totp]) alt key) --
        val exactFps = HashMap<String, MutableSet<String>>() // class NUL user NUL pass → totp fingerprints
        val siteUser = HashMap<String, Int>() // class NUL user → existing item count (rule 2 + seed)
        val altExact = HashMap<String, MutableSet<String>>() // name NUL pass → fingerprints (guard items)
        val noteExact = HashSet<String>() // name NUL notes (vault side CRLF/CR → LF)
        for (l in existing.logins) {
            val classes = l.uris.mapNotNull { uriClass(it) }.distinct().ifEmpty { listOf(NO_URI) }
            val fp = totpFp(l.totp)
            if (classes == listOf(NO_URI) && l.username.isEmpty()) {
                val set = altExact.getOrPut("${l.name}\u0000${l.password}") { HashSet() }
                if (fp != null) set.add(fp)
                // Rename-aware rule 1 (A9 inverse; 2026-07-09 review): a guard item stored as
                // "base (k)" — the shape an earlier import's rename minted — ALSO registers
                // under its stripped base name, so re-importing the same file resolves to
                // alreadyInVault instead of duplicating. Content (password[, totp]) equality
                // is still required, so a user's own literal "X (2)" can only skip a row
                // that is content-identical anyway.
                baseNameOf(l.name)?.let { base ->
                    val bset = altExact.getOrPut("$base\u0000${l.password}") { HashSet() }
                    if (fp != null) bset.add(fp)
                }
            } else {
                for (c in classes) {
                    val set = exactFps.getOrPut("$c\u0000${l.username}\u0000${l.password}") { HashSet() }
                    if (fp != null) set.add(fp)
                    siteUser["$c\u0000${l.username}"] = (siteUser["$c\u0000${l.username}"] ?: 0) + 1
                }
            }
        }
        for (n in existing.notes) {
            noteExact.add("${n.name}\u0000${toLf(n.notes)}")
            // Rename-aware rule 1 for notes (same rationale as the guard-login base key).
            baseNameOf(n.name)?.let { noteExact.add("$it\u0000${toLf(n.notes)}") }
        }
        val existingNames = existing.names.toHashSet()

        // -- in-file state --
        var skippedEmpty = 0
        var collapsed = 0
        val flagged = ArrayList<String>()
        val alreadyInVault = ArrayList<String>()
        val passwordDiffers = ArrayList<String>()
        val totpDiffers = ArrayList<String>()
        val totpUnsupported = ArrayList<String>()
        val noteItems = ArrayList<String>()
        val loginExactSeen = HashSet<String>() // uris,user,pass,totp — totp included so a row differing
        //                                        ONLY by its TOTP seed is not dropped as an exact dup
        val noteExactSeen = HashSet<String>() // name,notes (A1)
        val groupCount = HashMap<String, Int>() // raw url NUL user → last k used (lazy vault seed)
        val noteGroupCount = HashMap<String, Int>() // name → last k used
        val plannedNames = HashSet<String>()
        // A9 (2026-07-09 review): every literal row name in the FILE also blocks a mint —
        // a k=1 row keeps its name unconditionally (spec 06 §4), so a rename that fires
        // BEFORE a later row literally named "base (k)" must skip past it or one plan
        // would emit two identical display names. Includes rows that later skip
        // (collapsed/alreadyInVault/skippedEmpty) — an over-skip gap in the (k) sequence
        // is the already-tolerated freeName behavior.
        val fileLiteralNames = parsed.rows.mapTo(HashSet()) { it.name }
        val items = ArrayList<PlannedItem>()

        /** A9 — bump (k) until the display name is free in the vault, this plan, AND the file's literals. */
        fun freeName(base: String, startK: Int): Pair<String, Int> {
            var k = startK
            while (true) {
                val cand = "$base ($k)"
                if (cand !in existingNames && cand !in plannedNames && cand !in fileLiteralNames) return cand to k
                k++
            }
        }

        for (row in parsed.rows) {
            if (row.kind == RowKind.NOTE) {
                if (row.name.isEmpty() && row.notes.isEmpty()) { skippedEmpty++; continue }
                val key = "${row.name}\u0000${row.notes}"
                if (key in noteExact) { alreadyInVault.add(row.name); continue } // vault rule 1 (notes)
                if (!noteExactSeen.add(key)) { collapsed++; continue }
                var k = (noteGroupCount[row.name] ?: 0) + 1
                var name = row.name
                if (k >= 2) {
                    val (cand, usedK) = freeName(row.name, k)
                    name = cand; k = usedK
                    flagged.add(name)
                }
                noteGroupCount[row.name] = k
                plannedNames.add(name)
                noteItems.add(name)
                items.add(PlannedItem(newId(), ItemDoc(type = "note", name = name, notes = row.notes.ifEmpty { null }, favorite = row.favorite)))
                continue
            }

            // kind = LOGIN
            if (row.username.isEmpty() && row.password.isEmpty()) { skippedEmpty++; continue }
            val rowClass = uriClass(row.url) ?: NO_URI
            val bothEmpty = rowClass == NO_URI && row.username.isEmpty() // A7 empty-discriminator guard
            val fpRow = totpFp(row.totp)
            val fpSet = if (bothEmpty) altExact["${row.name}\u0000${row.password}"]
            else exactFps["$rowClass\u0000${row.username}\u0000${row.password}"]
            // vault rule 1 — exact match (totp wildcard when the file has no totp column)
            if (fpSet != null && (!parsed.totpColumn || (fpRow != null && fpRow in fpSet))) {
                alreadyInVault.add(row.name)
                continue
            }
            // vault rule 2 — same site+user, different secret (never fires under the guard)
            val vaultDiffers: String? = if (!bothEmpty && "$rowClass\u0000${row.username}" in siteUser) {
                if ("$rowClass\u0000${row.username}\u0000${row.password}" in exactFps) "totp" else "password"
            } else null
            // in-file exact collapse (raw values, NUL/SOH-joined)
            val exactKey = row.uris.joinToString("\u0001") + "\u0000" + row.username + "\u0000" + row.password + "\u0000" + (row.totp ?: "")
            if (!loginExactSeen.add(exactKey)) { collapsed++; continue }
            // in-file group, seeded from the vault so renames continue the visible sequence
            val gkey = "${row.url}\u0000${row.username}"
            var k = (groupCount[gkey] ?: (if (bothEmpty) 0 else siteUser["$rowClass\u0000${row.username}"] ?: 0)) + 1
            var name = row.name
            if (k >= 2) {
                val (cand, usedK) = freeName(row.name, k)
                name = cand; k = usedK
                when (vaultDiffers) {
                    "totp" -> totpDiffers.add(name) // password matched an existing item; only the seed differs
                    "password" -> passwordDiffers.add(name) // includes rows where BOTH differ (pinned)
                    else -> flagged.add(name) // purely in-file duplicate
                }
            }
            groupCount[gkey] = k
            plannedNames.add(name)
            if (row.totpUnsupported) totpUnsupported.add(name)
            items.add(
                PlannedItem(
                    newId(),
                    ItemDoc(
                        type = "login",
                        name = name,
                        notes = row.notes.ifEmpty { null },
                        favorite = row.favorite,
                        login = LoginData(
                            username = row.username,
                            password = row.password,
                            uris = row.uris,
                            totp = row.totp,
                        ),
                    ),
                ),
            )
        }
        return ImportPlan(
            items,
            ImportReport(
                imported = items.size,
                skippedEmpty = skippedEmpty,
                collapsed = collapsed,
                flagged = flagged,
                alreadyInVault = alreadyInVault,
                passwordDiffers = passwordDiffers,
                totpDiffers = totpDiffers,
                archivedSkipped = parsed.archivedSkipped,
                unknownTypeSkipped = parsed.unknownTypeSkipped,
                totpUnsupported = totpUnsupported,
                noteItems = noteItems,
                errors = parsed.errors,
            ),
        )
    }

    // ---- plan keying helpers (A7) ----

    private const val NO_URI = "-" // sentinel class: no parseable uri ([] and [""] are the same)

    /** The A9 rename shape, pinned ASCII (never platform \d): `base (k)` → base, else null.
     *  Strips ONE suffix (matching what one freeName mint appends); web twin: csv.ts baseNameOf. */
    private val RENAMED = Regex("^(.+) \\(([0-9]+)\\)$")
    private fun baseNameOf(name: String): String? = RENAMED.matchEntire(name)?.groupValues?.get(1)

    /** Url equality class per spec 02 §3.1 — [UriMatch.parseSavedUri]; null (EMPTY only)
     *  → the NO_URI sentinel at call sites. A non-empty uri that fails to parse (A5 junk
     *  like ".example.com" — parseable before 2026-07-10) keys a verbatim `j:` class
     *  instead of dropping: dropping collapsed junk-uri-only items into NO_URI, where a
     *  re-import could false-merge rows differing only by that junk uri (web csv.ts twin). */
    private fun uriClass(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        return when (val s = UriMatch.parseSavedUri(trimmed)) {
            is SavedUri.Web -> "w:${s.host}"
            is SavedUri.AndroidApp -> "a:${s.pkg}"
            null -> "j:${trimmed.lowercase()}"
        }
    }

    /** TOTP fingerprint for rules 1–2 (A7): compared by PARSED parameters (secret bytes +
     *  algorithm + digits + period, label/issuer ignored), never raw strings. Both sides go
     *  through [Totp.normalize] first. null/"" → ABSENT (matches absent); a value the
     *  parser rejects → null = never equal to anything (import it and let the user review). */
    private fun totpFp(raw: String?): String? {
        if (raw == null || raw.isEmpty()) return "-"
        val cfg = try { Totp.parseUri(Totp.normalize(raw)) } catch (e: CryptoException) { return null }
        return "p\u0001" + cfg.secret.joinToString(",") { it.toString() } +
            "\u0001" + cfg.algorithm.name + "\u0001" + cfg.digits + "\u0001" + cfg.periodSeconds
    }

    /** Vault-side note bodies normalize CRLF / lone CR → LF before rule-1 comparison (A7) —
     *  the CSV reader already yields LF on the file side. */
    private fun toLf(s: String): String {
        if ('\r' !in s) return s
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\r') {
                sb.append('\n')
                if (i + 1 < s.length && s[i + 1] == '\n') i++
            } else sb.append(c)
            i++
        }
        return sb.toString()
    }

    /** spec 06 §4.7 — pinned host extraction (no URL library). */
    internal fun nameFallback(url: String): String {
        var s = url.csvTrim()
        if (s.isEmpty()) return "Imported login"
        val scheme = Regex("^[A-Za-z][A-Za-z0-9+.\\-]*://")
        s = scheme.replace(s, "")
        val cut = s.indexOfFirst { it == '/' || it == '?' || it == '#' }
        if (cut >= 0) s = s.substring(0, cut)
        val at = s.lastIndexOf('@')
        if (at >= 0) s = s.substring(at + 1)
        s = if (s.startsWith("[")) {
            val close = s.indexOf(']')
            if (close >= 0) s.substring(1, close) else s.drop(1) // IPv6 bracket contents
        } else {
            val colon = s.lastIndexOf(':') // strip a trailing :digits port only
            if (colon >= 0 && colon < s.length - 1 && s.substring(colon + 1).all { it.isDigit() }) s.substring(0, colon) else s
        }
        s = s.lowercase()
        return if (s.isNotEmpty()) s else url.csvTrim().ifEmpty { "Imported login" }
    }
}

/** RFC 4180 state machine (spec 06 §4.3) with the pinned lenient rules. */
internal object Rfc4180 {
    class RawRecord(val fields: List<String>, val line: Int, val badQuote: Boolean)

    /** Length of a newline at [i]: 2 (CRLF), 1 (lone CR / LF), 0 (none). */
    private fun nl(text: String, i: Int): Int {
        val c = text[i]
        if (c == '\r') return if (i + 1 < text.length && text[i + 1] == '\n') 2 else 1
        if (c == '\n') return 1
        return 0
    }

    fun parse(text: String): List<RawRecord> {
        val out = ArrayList<RawRecord>()
        var i = 0
        val n = text.length
        var line = 1
        while (i < n) {
            val recLine = line
            val fields = ArrayList<String>()
            val f = StringBuilder()
            var badQuote = false
            var endOfRecord = false
            while (!endOfRecord) {
                if (i >= n) { fields.add(f.toString()); endOfRecord = true; break }
                val c = text[i]
                if (c == '"' && f.isEmpty()) {
                    i++ // opening quote
                    var closed = false
                    while (i < n) {
                        val q = text[i]
                        if (q == '"') {
                            if (i + 1 < n && text[i + 1] == '"') { f.append('"'); i += 2 } else { i++; closed = true; break }
                        } else {
                            val len = nl(text, i)
                            if (len > 0) { f.append('\n'); line++; i += len } else { f.append(q); i++ }
                        }
                    }
                    if (!closed) badQuote = true // EOF inside a quoted field
                    if (closed) while (i < n && nl(text, i) == 0 && text[i] != ',') { badQuote = true; i++ } // junk after close quote
                    when {
                        i < n && text[i] == ',' -> { fields.add(f.toString()); f.clear(); i++ }
                        else -> {
                            fields.add(f.toString()); f.clear()
                            val len = if (i < n) nl(text, i) else 0
                            if (len > 0) { line++; i += len }
                            endOfRecord = true
                        }
                    }
                } else if (c == ',') {
                    fields.add(f.toString()); f.clear(); i++
                } else {
                    val len = nl(text, i)
                    if (len > 0) { fields.add(f.toString()); f.clear(); line++; i += len; endOfRecord = true } else { f.append(c); i++ }
                }
            }
            out.add(RawRecord(fields, recLine, badQuote))
        }
        return out
    }
}
