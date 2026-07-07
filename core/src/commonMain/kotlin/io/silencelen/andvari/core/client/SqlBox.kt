package io.silencelen.andvari.core.client

/**
 * Minimal SQLite driver shim for the durable client cache (spec 02 §8). Two actuals:
 * JDBC (desktop/JVM tests, xerial — the driver the server already proves) and the
 * Android framework database (no dependency, no Context needed).
 *
 * Contract constraints (Android framework limits, kept symmetric on JVM):
 *  - bind args are String | Long | Int | null; the Android actual converts numbers to
 *    String for rawQuery, so WHERE clauses MUST compare TEXT columns only (all current
 *    queries are PK-by-TEXT; numeric filtering happens in memory).
 *  - statements that return rows must go through [query]; PRAGMAs that return rows
 *    (e.g. journal_mode) are handled inside the actuals, never via [exec].
 */
interface SqlRow {
    fun string(i: Int): String?
    fun long(i: Int): Long
    fun int(i: Int): Int
}

interface SqlBox : AutoCloseable {
    fun exec(sql: String, vararg args: Any?)
    fun <T> query(sql: String, vararg args: Any?, map: (SqlRow) -> T): List<T>
    fun tx(block: () -> Unit)
    var userVersion: Int
}

/** Platform factory; creates the file (and parent dirs) as needed. */
expect fun openSqlBox(path: String): SqlBox
