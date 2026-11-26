package io.silencelen.andvari.cli

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Where the tool turns a restore record's name into a path, a name of anything but lower-case letters, digits and
 * hyphens is refused, so the path stays in the home even if the check of the file's id were ever lost.
 */
class RestoreRecordFilesTest {
    @Test fun aRecordNameThatIsNoSafeNameIsRefusedBeforeAPathIsMade() {
        val base = Files.createTempDirectory("andvari-records").toFile()
        val home = base.resolve("home").also { it.mkdirs() }
        val files = RecordFiles(home)
        val bad = listOf("../escaped", "x/../../escaped", "a/b", "a\\b", "Restore-A", "..", "", "x" + Char(0) + "y", "a".repeat(4000), "restore-x.json")
        for (name in bad) {
            assertFailsWith<CliError>(name) { files.replace(name, "{}") }
            assertFailsWith<CliError>(name) { files.read(name) }
            assertFailsWith<CliError>(name) { files.remove(name) }
        }
        assertEquals(setOf("home"), base.walkTopDown().map { it.relativeTo(base).path }.filter { it.isNotEmpty() }.toSet(), "nothing was made")
        files.replace("restore-eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee-0123456789abcdef", "{}")
        assertEquals("{}", files.read("restore-eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee-0123456789abcdef"))
    }
}
