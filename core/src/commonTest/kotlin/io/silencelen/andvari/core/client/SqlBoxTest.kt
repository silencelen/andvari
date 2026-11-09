package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.deleteDir
import io.silencelen.andvari.core.newTempDir
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** The driver contract the vault cache relies on, run against every platform's actual. */
class SqlBoxTest {
    private val dir = newTempDir("andvari-sqlbox")
    private val path = "$dir/nested/box.db"

    @AfterTest fun cleanup() = deleteDir(dir)

    private fun <T> withBox(block: (SqlBox) -> T): T = openSqlBox(path).use { box ->
        box.exec("CREATE TABLE IF NOT EXISTS t (k TEXT PRIMARY KEY, v TEXT, n INTEGER)")
        block(box)
    }

    private fun SqlBox.value(k: String): String? = query("SELECT v FROM t WHERE k = ?", k) { it.string(0) }.single()

    @Test fun textRoundTripsAndEmptyIsNotNull() = withBox { box ->
        val samples = mapOf("empty" to "", "ascii" to "plain", "accent" to "café", "astral" to "😀 ok", "cjk" to "中文")
        for ((k, v) in samples) box.exec("INSERT INTO t (k, v) VALUES (?, ?)", k, v)
        for ((k, v) in samples) assertEquals(v, box.value(k), k)
    }

    @Test fun nullBindsAsNull() = withBox { box ->
        box.exec("INSERT INTO t (k, v) VALUES (?, ?)", "a", null)
        assertNull(box.value("a"))
    }

    @Test fun numbersRoundTrip() = withBox { box ->
        box.exec("INSERT INTO t (k, n) VALUES (?, ?)", "max", Long.MAX_VALUE)
        box.exec("INSERT INTO t (k, n) VALUES (?, ?)", "neg", -5)
        assertEquals(Long.MAX_VALUE, box.query("SELECT n FROM t WHERE k = ?", "max") { it.long(0) }.single())
        assertEquals(-5, box.query("SELECT n FROM t WHERE k = ?", "neg") { it.int(0) }.single())
    }

    @Test fun aFailedTransactionRollsBack() = withBox { box ->
        assertFailsWith<IllegalStateException> {
            box.tx {
                box.exec("INSERT INTO t (k, v) VALUES (?, ?)", "gone", "x")
                error("abort")
            }
        }
        assertEquals(emptyList(), box.query("SELECT k FROM t WHERE k = ?", "gone") { it.string(0) })
    }

    @Test fun aCommittedTransactionPersists() {
        withBox { box -> box.tx { box.exec("INSERT INTO t (k, v) VALUES (?, ?)", "kept", "y") } }
        withBox { box -> assertEquals("y", box.value("kept")) }
    }

    @Test fun userVersionPersists() {
        withBox { box ->
            assertEquals(0, box.userVersion)
            box.userVersion = 7
        }
        withBox { box -> assertEquals(7, box.userVersion) }
    }

    @Test fun aBadStatementThrows() = withBox { box ->
        assertFailsWith<Exception> { box.exec("NOT SQL") }
        Unit
    }
}
