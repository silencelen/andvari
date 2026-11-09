@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.client

import kotlinx.cinterop.*
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.create
import platform.Foundation.stringByDeletingLastPathComponent
import platform.sqlite3.*

/** SQLite's "copy this buffer" destructor sentinel; the C macro does not cross cinterop. */
private val TRANSIENT = (-1L).toCPointer<CFunction<(COpaquePointer?) -> Unit>>()

/** iOS actual over the system SQLite. Same connection settings as the JDBC actual. */
private class NativeSqlBox(path: String) : SqlBox {
    private val db: CPointer<sqlite3>

    init {
        val parent = NSString.create(string = path).stringByDeletingLastPathComponent
        if (parent.isNotEmpty()) {
            NSFileManager.defaultManager.createDirectoryAtPath(parent, withIntermediateDirectories = true, attributes = null, error = null)
        }
        db = memScoped {
            val out = alloc<CPointerVar<sqlite3>>()
            val rc = sqlite3_open_v2(path, out.ptr, SQLITE_OPEN_READWRITE or SQLITE_OPEN_CREATE or SQLITE_OPEN_FULLMUTEX, null)
            val handle = out.value
            if (rc != SQLITE_OK || handle == null) {
                if (handle != null) sqlite3_close_v2(handle)
                error("sqlite open failed: $rc")
            }
            handle
        }
        sqlite3_busy_timeout(db, 5000)
        pragma("PRAGMA journal_mode=WAL")
        pragma("PRAGMA foreign_keys=ON")
    }

    private fun fail(what: String): Nothing = error("sqlite $what failed: ${sqlite3_errmsg(db)?.toKString()}")

    private inline fun <R> statement(sql: String, args: Array<out Any?>, block: (CPointer<sqlite3_stmt>) -> R): R {
        val stmt = memScoped {
            val out = alloc<CPointerVar<sqlite3_stmt>>()
            if (sqlite3_prepare_v2(db, sql, -1, out.ptr, null) != SQLITE_OK) fail("prepare")
            out.value ?: fail("prepare (empty statement)")
        }
        try {
            args.forEachIndexed { i, a -> bind(stmt, i + 1, a) }
            return block(stmt)
        } finally {
            sqlite3_finalize(stmt)
        }
    }

    private fun bind(stmt: CPointer<sqlite3_stmt>, index: Int, value: Any?) {
        val rc = when (value) {
            null -> sqlite3_bind_null(stmt, index)
            is Long -> sqlite3_bind_int64(stmt, index, value)
            is Int -> sqlite3_bind_int(stmt, index, value)
            is String -> {
                // An explicit byte length keeps embedded NULs. A real pointer, even for "", because a
                // NULL pointer would bind SQL NULL instead of the empty string.
                val bytes = value.encodeToByteArray()
                (if (bytes.isEmpty()) ByteArray(1) else bytes).usePinned {
                    sqlite3_bind_text(stmt, index, it.addressOf(0), bytes.size, TRANSIENT)
                }
            }
            else -> error("unsupported bind type ${value::class}")
        }
        if (rc != SQLITE_OK) fail("bind")
    }

    /** A PRAGMA may return a row, which [exec] would treat as a misuse. */
    private fun pragma(sql: String) = statement(sql, emptyArray()) { stmt -> while (sqlite3_step(stmt) == SQLITE_ROW) { /* drain */ } }

    override fun exec(sql: String, vararg args: Any?) {
        statement(sql, args) { stmt ->
            var rc = sqlite3_step(stmt)
            while (rc == SQLITE_ROW) rc = sqlite3_step(stmt)
            if (rc != SQLITE_DONE) fail("step")
        }
    }

    override fun <T> query(sql: String, vararg args: Any?, map: (SqlRow) -> T): List<T> = statement(sql, args) { stmt ->
        val row = object : SqlRow {
            override fun string(i: Int): String? {
                val text = sqlite3_column_text(stmt, i) ?: return null
                return text.reinterpret<ByteVar>().readBytes(sqlite3_column_bytes(stmt, i)).decodeToString()
            }
            override fun long(i: Int): Long = sqlite3_column_int64(stmt, i)
            override fun int(i: Int): Int = sqlite3_column_int(stmt, i)
        }
        buildList {
            while (true) {
                when (sqlite3_step(stmt)) {
                    SQLITE_ROW -> add(map(row))
                    SQLITE_DONE -> break
                    else -> fail("step")
                }
            }
        }
    }

    override fun tx(block: () -> Unit) {
        exec("BEGIN")
        try {
            block()
            exec("COMMIT")
        } catch (t: Throwable) {
            exec("ROLLBACK")
            throw t
        }
    }

    override var userVersion: Int
        get() = query("PRAGMA user_version") { it.int(0) }.firstOrNull() ?: 0
        set(value) { pragma("PRAGMA user_version = $value") }

    override fun close() {
        sqlite3_close_v2(db)
    }
}

actual fun openSqlBox(path: String): SqlBox = NativeSqlBox(path)
