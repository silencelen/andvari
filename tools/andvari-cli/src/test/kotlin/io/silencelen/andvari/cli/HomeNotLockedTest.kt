package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A home whose lock file cannot be opened: the command stops before it reads or sends anything, with its own sentence and
 * key ([HOME_NOT_LOCKED], [KEY_HOME_NOT_LOCKED]). Before, the sentence had no key.
 */
class HomeNotLockedTest {
    @Test fun aHomeThatCannotBeLockedStopsWithItsKey() {
        TestServer().use { s ->
            val home = kotlin.io.path.createTempDirectory("andvari-cli-nolock").toFile()
            // A directory where the lock file goes: the system refuses to open it for writing.
            File(home, HomeLock.FILE_NAME).mkdirs()
            val r = CliRun.run(s, home, "whoami")
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$KEY_HOME_NOT_LOCKED]: "), r.err)
            assertTrue(r.err.contains(fill(HOME_NOT_LOCKED, home.path, "").substringBefore(" ()")), r.err)
        }
    }
}
