package io.silencelen.andvari.core.client

import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement

/** JDBC actual (desktop + JVM tests) over the already-catalogued xerial driver. */
private class JdbcSqlBox(path: String) : SqlBox {
    private val conn: Connection

    init {
        File(path).parentFile?.mkdirs()
        conn = DriverManager.getConnection("jdbc:sqlite:$path")
        conn.autoCommit = true
        conn.createStatement().use { st ->
            st.execute("PRAGMA journal_mode=WAL")
            st.execute("PRAGMA foreign_keys=ON")
            st.execute("PRAGMA busy_timeout=5000")
        }
    }

    private fun PreparedStatement.bind(args: Array<out Any?>): PreparedStatement {
        args.forEachIndexed { i, a ->
            when (a) {
                null -> setObject(i + 1, null)
                is String -> setString(i + 1, a)
                is Long -> setLong(i + 1, a)
                is Int -> setInt(i + 1, a)
                else -> error("unsupported bind type ${a::class}")
            }
        }
        return this
    }

    override fun exec(sql: String, vararg args: Any?) {
        conn.prepareStatement(sql).use { it.bind(args).executeUpdate() }
    }

    override fun <T> query(sql: String, vararg args: Any?, map: (SqlRow) -> T): List<T> =
        conn.prepareStatement(sql).use { st ->
            st.bind(args).executeQuery().use { rs ->
                val row = object : SqlRow {
                    override fun string(i: Int): String? = rs.getString(i + 1)
                    override fun long(i: Int): Long = rs.getLong(i + 1)
                    override fun int(i: Int): Int = rs.getInt(i + 1)
                }
                buildList { while (rs.next()) add(map(row)) }
            }
        }

    override fun tx(block: () -> Unit) {
        conn.autoCommit = false
        try {
            block()
            conn.commit()
        } catch (t: Throwable) {
            conn.rollback()
            throw t
        } finally {
            conn.autoCommit = true
        }
    }

    override var userVersion: Int
        get() = conn.createStatement().use { st ->
            st.executeQuery("PRAGMA user_version").use { rs -> if (rs.next()) rs.getInt(1) else 0 }
        }
        set(value) {
            conn.createStatement().use { it.execute("PRAGMA user_version = $value") }
        }

    override fun close() = conn.close()
}

actual fun openSqlBox(path: String): SqlBox = JdbcSqlBox(path)
