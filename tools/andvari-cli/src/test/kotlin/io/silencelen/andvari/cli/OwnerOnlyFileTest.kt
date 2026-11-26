package io.silencelen.andvari.cli

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A file the tool writes for a secret (`operator escrow --out`, `--kit-out`, the device's own
 * state) goes through a temporary file with an unpredictable name, created so that it fails if the name exists, readable
 * by the owner only, in the same directory, then renamed over the target. Before, it went through `<name>.tmp`: a
 * predictable name, deleted first if something stood there, which in a directory others can write let them aim it.
 */
class OwnerOnlyFileTest {
    @Test fun aSecretIsWrittenThroughAnUnpredictableOwnerOnlyFileThatNeverReusesAName() {
        val dir = Files.createTempDirectory("andvari-cli-owner-only").toFile()
        val target = File(dir, "escrow.json")
        // What another user of the directory put at the old predictable name: left exactly as it was.
        val decoy = File(dir, "escrow.json.tmp").apply { writeText("someone else's file\n") }
        OwnerOnlyFile(target).replace("{\"secret\":1}")
        assertEquals("{\"secret\":1}", target.readText())
        assertEquals("someone else's file\n", decoy.readText(), "the file at the predictable name was touched")
        assertEquals(setOf("escrow.json", "escrow.json.tmp"), dir.list()!!.toSet(), "no temporary file is left behind")
        if (Files.getFileStore(dir.toPath()).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(target.toPath())))
        }

        // A second write replaces the content whole; the decoy still stands.
        OwnerOnlyFile(target).replace("{\"secret\":2}")
        assertEquals("{\"secret\":2}", target.readText())
        assertEquals("someone else's file\n", decoy.readText())

        // A symbolic link at the old name to a file elsewhere is neither followed nor removed.
        val elsewhere = File(dir, "victim.txt").apply { writeText("victim\n") }
        decoy.delete()
        val link = File(dir, "escrow.json.tmp").toPath()
        val linked = runCatching { Files.createSymbolicLink(link, elsewhere.toPath()) }.isSuccess
        OwnerOnlyFile(target).replace("{\"secret\":3}")
        assertEquals("{\"secret\":3}", target.readText())
        assertEquals("victim\n", elsewhere.readText())
        if (linked) assertTrue(Files.isSymbolicLink(link), "the link at the old name was removed")
        assertTrue(dir.listFiles()!!.none { it.name.startsWith(".escrow.json.") }, "no temporary file is left behind")
    }
}
