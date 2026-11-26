package io.silencelen.andvari.server

import org.sqlite.SQLiteConfig
import org.sqlite.SQLiteOpenMode
import java.io.File
import java.sql.DriverManager
import java.sql.SQLException

/**
 * SQLite's integrity check (`PRAGMA integrity_check`) as the snapshot command runs it on a new snapshot and
 * `andvari admin restored` runs it on a put-back database before it changes anything (decided on 22 November 2026).
 * [passed] is the one rule both commands judge the answer by.
 */
object IntegrityCheck {
    /** The check passed: it answered exactly one row, `ok`. Any other answer names a fault. */
    fun passed(answers: List<String>): Boolean = answers == listOf("ok")

    /** What the check found on a file. */
    sealed class Result {
        /**
         * The check passed. [baseline] is the database's marker as its settings table holds it, read in the same opening;
         * null where it has no settings table or no marker (another program's database).
         */
        class Passed(val baseline: String?) : Result()

        /** The file has no bytes: SQLite would take it for an empty database and answer `ok`, so it is said first. */
        object Empty : Result()

        /** The check ran and named faults: its first answers. */
        class Faults(val answers: List<String>) : Result()

        /** SQLite could not read the file as a database, or could not open it: its error code and words. */
        class Unreadable(val code: Int, val message: String) : Result()
    }

    /**
     * Runs the check on the database file [file] as it lies, opened read only and `immutable`: SQLite then takes no lock,
     * reads no write-ahead file or journal beside it and makes, removes or changes no file in its folder, so the folder is
     * byte for byte as it was whatever the check finds. Only for a file with nothing beside it (a write-ahead file beside
     * it would not be read). Where the check passes, the database's marker is read in the same opening.
     */
    fun onFileAsItIs(file: File): Result {
        if (file.length() == 0L) return Result.Empty
        val config = SQLiteConfig().apply {
            setReadOnly(true)
            setOpenMode(SQLiteOpenMode.OPEN_URI)
        }
        val uri = "file:" + file.absoluteFile.toURI().rawPath + "?immutable=1"
        return try {
            DriverManager.getConnection("jdbc:sqlite:$uri", config.toProperties()).use { c ->
                val answers = c.queryAll("PRAGMA integrity_check") { it.getString(1) }
                if (!passed(answers)) return@use Result.Faults(answers.take(3))
                val hasMeta = c.queryOne("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'") { it.getLong(1) } ?: 0L
                Result.Passed(if (hasMeta > 0) c.queryOne("SELECT value FROM meta WHERE key='baseline'") { it.getString(1) } else null)
            }
        } catch (e: SQLException) {
            Result.Unreadable(e.errorCode and 0xff, e.message ?: e.toString())
        }
    }
}
