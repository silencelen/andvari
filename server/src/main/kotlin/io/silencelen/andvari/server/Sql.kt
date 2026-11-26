package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import java.security.MessageDigest
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.util.UUID

/*
 * Plain JDBC helpers. Every statement the server runs goes through [exec], [queryOne] or [queryAll],
 * which bind every value as a parameter: there is no string-built SQL with request data in it anywhere
 * (spec 03's security rules for the server: parameterised SQL only).
 */

private fun PreparedStatement.bind(vararg args: Any?): PreparedStatement {
    args.forEachIndexed { i, a ->
        when (a) {
            null -> setNull(i + 1, java.sql.Types.NULL)
            is String -> setString(i + 1, a)
            is Int -> setInt(i + 1, a)
            is Long -> setLong(i + 1, a)
            is Boolean -> setInt(i + 1, if (a) 1 else 0)
            is ByteArray -> setBytes(i + 1, a)
            else -> error("unsupported bind type ${a::class}")
        }
    }
    return this
}

fun Connection.exec(sql: String, vararg args: Any?): Int =
    prepareStatement(sql).use { it.bind(*args).executeUpdate() }

fun <T> Connection.queryOne(sql: String, vararg args: Any?, map: (ResultSet) -> T): T? =
    prepareStatement(sql).use { st -> st.bind(*args).executeQuery().use { rs -> if (rs.next()) map(rs) else null } }

fun <T> Connection.queryAll(sql: String, vararg args: Any?, map: (ResultSet) -> T): List<T> =
    prepareStatement(sql).use { st ->
        st.bind(*args).executeQuery().use { rs ->
            val out = ArrayList<T>()
            while (rs.next()) out.add(map(rs))
            out
        }
    }

fun Connection.count(sql: String, vararg args: Any?): Long = queryOne(sql, *args) { it.getLong(1) } ?: 0L

fun ResultSet.longOrNull(col: String): Long? = getLong(col).let { if (wasNull()) null else it }

fun ResultSet.bool(col: String): Boolean = getInt(col) != 0

/** Lowercase canonical UUIDv4, the id form used everywhere (spec 00). */
fun uuid(): String = UUID.randomUUID().toString()

/** Lowercase hex SHA-256 of the UTF-8 bytes of [s]. */
fun sha256Hex(s: String): String = Bytes.toHexLower(MessageDigest.getInstance("SHA-256").digest(s.encodeToByteArray()))

/** Lowercase hex SHA-256 of [b]. */
fun sha256Hex(b: ByteArray): String = Bytes.toHexLower(MessageDigest.getInstance("SHA-256").digest(b))

private val stringList = ListSerializer(String.serializer())
fun encodeIds(ids: List<String>): String = WireJson.json.encodeToString(stringList, ids)
fun decodeIds(text: String): List<String> = WireJson.json.decodeFromString(stringList, text)
fun encodeParams(p: KdfParams): String = WireJson.json.encodeToString(KdfParams.serializer(), p)
fun decodeParams(text: String): KdfParams = WireJson.json.decodeFromString(KdfParams.serializer(), text)
