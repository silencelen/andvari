package io.silencelen.andvari.core.client

import android.database.sqlite.SQLiteDatabase
import java.io.File

/**
 * Android framework actual — needs no Context (openOrCreateDatabase by absolute path)
 * and no dependency. WAL via enableWriteAheadLogging (execSQL of a row-returning
 * PRAGMA throws on Android); rawQuery binds are String[]-only, so numeric args are
 * stringified — acceptable per the SqlBox contract (TEXT-column WHEREs only).
 */
private class AndroidSqlBox(path: String) : SqlBox {
    private val db: SQLiteDatabase

    init {
        File(path).parentFile?.mkdirs()
        db = SQLiteDatabase.openOrCreateDatabase(File(path), null)
        db.enableWriteAheadLogging()
        db.execSQL("PRAGMA foreign_keys=ON")
    }

    override fun exec(sql: String, vararg args: Any?) {
        if (args.isEmpty()) db.execSQL(sql) else db.execSQL(sql, args)
    }

    override fun <T> query(sql: String, vararg args: Any?, map: (SqlRow) -> T): List<T> {
        val bind = args.map { it?.toString() }.toTypedArray()
        db.rawQuery(sql, bind).use { c ->
            val row = object : SqlRow {
                override fun string(i: Int): String? = if (c.isNull(i)) null else c.getString(i)
                override fun long(i: Int): Long = c.getLong(i)
                override fun int(i: Int): Int = c.getInt(i)
            }
            return buildList { while (c.moveToNext()) add(map(row)) }
        }
    }

    override fun tx(block: () -> Unit) {
        db.beginTransaction()
        try {
            block()
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    override var userVersion: Int
        get() = db.version
        set(value) { db.version = value }

    override fun close() = db.close()
}

actual fun openSqlBox(path: String): SqlBox = AndroidSqlBox(path)
